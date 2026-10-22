package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCoapDTLSWireOracle(t *testing.T) {
	token := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	request := uint32(6)
	var scratch [32]byte
	got := coapRequest(0x1234, token, &request, true, &scratch)
	if !bytes.Equal(got[12:], []byte{0xb5, 'b', 'e', 'n', 'c', 'h', 0xc1, 6}) {
		t.Fatal("request wire changed")
	}
	base := append([]byte{0x68, 69, 0x12, 0x34}, token[:]...)
	valid := append(bytes.Clone(base), 0xc1, 42, 0xb1, 6, 255, 0, 1, 2)
	reply, err := decodeCoap(valid, token)
	if err != nil || reply.block == nil || *reply.block != 6 || !bytes.Equal(reply.body, []byte{0, 1, 2}) {
		t.Fatalf("valid reply: %v", err)
	}
	for name, wire := range map[string][]byte{
		"missing-format":   append(bytes.Clone(base), 255, 0),
		"wrong-format":     append(bytes.Clone(base), 0xc1, 0, 255, 0),
		"duplicate-format": append(bytes.Clone(base), 0xc1, 42, 0x01, 42, 255, 0),
		"BERT":             append(bytes.Clone(base), 0xc1, 42, 0xb1, 7, 255, 0),
		"truncated-option": append(bytes.Clone(base), 0xcd, 5),
		"critical-option":  append(bytes.Clone(base), 0xb1, 0, 255, 0),
	} {
		if _, err := decodeCoap(wire, token); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestDTLSCredentialsAndEndpointBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 24), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := dtlsConfig(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.PSK([]byte("wrong")); err == nil {
		t.Fatal("wrong identity accepted")
	}
	if _, err := config.PSK(nil); err == nil {
		t.Fatal("missing client identity accepted by server")
	}
	key, err := config.PSK([]byte("benchmark"))
	if err != nil || len(key) != 16 {
		t.Fatal("PSK profile")
	}
	client, err := dtlsConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, hint := range [][]byte{nil, {}, []byte("benchmark")} {
		got, err := client.PSK(hint)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatal("optional/known server hint did not select the authenticated PSK")
		}
	}
	if _, err := client.PSK([]byte("unknown")); err == nil {
		t.Fatal("unknown nonempty server hint accepted")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 25), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := dtlsConfig(path, false); err == nil {
		t.Fatal("trailing credentials accepted")
	}
	if dtlsEndpointBound(65536, 4, 64, 1) != 8 || dtlsEndpointBound(640000, 1, 1500, 0) != 1500 {
		t.Fatal("endpoint bound")
	}
}
