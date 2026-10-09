package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	coap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	"github.com/quic-go/quic-go/http3"
)

func payload(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}

func certificate(path string) (tls.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "benchmark-localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, nil
}

func server(protocol, address string, size int, certFile string) error {
	body := payload(size)
	if protocol == "coap" {
		router := mux.NewRouter()
		router.Handle("/bench", mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
			if r.Code() != codes.GET {
				_ = w.SetResponse(codes.MethodNotAllowed, message.TextPlain, bytes.NewReader(nil))
				return
			}
			_ = w.SetResponse(codes.Content, message.AppOctets, bytes.NewReader(body))
		}))
		return coap.ListenAndServe("udp", address, router)
	}
	if protocol != "http3" {
		return fmt.Errorf("unsupported protocol")
	}
	cert, err := certificate(certFile)
	if err != nil {
		return err
	}
	handler := http.NewServeMux()
	handler.HandleFunc("/bench", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
	listener := &http3.Server{Addr: address, Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
	return listener.ListenAndServe()
}

type sample struct {
	Schema            string  `json:"schema"`
	Protocol          string  `json:"protocol"`
	Security          string  `json:"security"`
	Mode              string  `json:"mode"`
	Concurrency       int     `json:"concurrency"`
	Warmup            int     `json:"warmup"`
	Attempted         int     `json:"attempted"`
	Completed         int     `json:"completed"`
	Failed            int     `json:"failed"`
	WarmupFailed      int     `json:"warmup_failed"`
	VerifiedBytes     int     `json:"verified_bytes"`
	ElapsedNS         int64   `json:"elapsed_ns"`
	Latencies         []int64 `json:"latencies_ns"`
	Clock             string  `json:"clock"`
	ClockResolutionNS *int64  `json:"clock_resolution_ns"`
}

func load(address string, size, concurrency, operations, warmup, timeoutMS int, mode, certFile string) (sample, error) {
	if mode != "warm" && mode != "cold" {
		return sample{}, fmt.Errorf("HTTP3 mode")
	}
	rootBytes, err := os.ReadFile(certFile)
	if err != nil {
		return sample{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootBytes) {
		return sample{}, fmt.Errorf("invalid fixture trust root")
	}
	body := payload(size)
	makeClient := func() (*http.Client, *http3.Transport) {
		transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
		return &http.Client{Transport: transport, Timeout: time.Duration(timeoutMS) * time.Millisecond}, transport
	}
	client, transport := makeClient()
	defer transport.Close()
	request := func() (int64, error) {
		start := stamp()
		active := client
		var coldTransport *http3.Transport
		if mode == "cold" {
			active, coldTransport = makeClient()
		}
		response, err := active.Get("https://" + address + "/bench")
		if err == nil {
			value, readErr := io.ReadAll(io.LimitReader(response.Body, int64(size)+1))
			closeErr := response.Body.Close()
			if readErr != nil {
				err = readErr
			} else if closeErr != nil {
				err = closeErr
			} else if response.StatusCode != 200 || response.ProtoMajor != 3 || !bytes.Equal(value, body) {
				err = fmt.Errorf("representation or HTTP3 status mismatch")
			}
		}
		elapsed := stamp() - start
		if coldTransport != nil {
			_ = coldTransport.Close()
		}
		return elapsed, err
	}
	result := sample{Schema: "coaptic-load/1", Protocol: "http3", Security: "TLS1.3", Mode: mode, Concurrency: concurrency, Warmup: warmup, Attempted: operations, Clock: clockName, ClockResolutionNS: clockResolutionNS, Latencies: make([]int64, 0, operations)}
	var mutex sync.Mutex
	var ready sync.WaitGroup
	var finished sync.WaitGroup
	startGate := make(chan struct{})
	ready.Add(concurrency)
	finished.Add(concurrency)
	for worker := 0; worker < concurrency; worker++ {
		count := operations / concurrency
		if worker < operations%concurrency {
			count++
		}
		go func(count int) {
			defer finished.Done()
			warmupFailed := 0
			for i := 0; i < warmup; i++ {
				if _, err := request(); err != nil {
					warmupFailed++
				}
			}
			mutex.Lock()
			result.WarmupFailed += warmupFailed
			mutex.Unlock()
			ready.Done()
			<-startGate
			local := make([]int64, 0, count)
			failed := 0
			for i := 0; i < count; i++ {
				elapsed, err := request()
				if err != nil {
					failed++
				} else {
					local = append(local, elapsed)
				}
			}
			mutex.Lock()
			result.Latencies = append(result.Latencies, local...)
			result.Failed += failed
			mutex.Unlock()
		}(count)
	}
	ready.Wait()
	start := stamp()
	close(startGate)
	finished.Wait()
	result.ElapsedNS = stamp() - start
	result.Completed = len(result.Latencies)
	result.VerifiedBytes = result.Completed * size
	return result, nil
}

func main() {
	args := os.Args
	if len(args) < 7 {
		fmt.Fprintln(os.Stderr, "server PROTOCOL HOST PORT BYTES CERT; load HOST PORT BYTES CONCURRENCY OPERATIONS WARMUP TIMEOUT_MS MODE CERT")
		os.Exit(2)
	}
	size, err := strconv.Atoi(args[5])
	if args[1] == "load" {
		size, err = strconv.Atoi(args[4])
	}
	if err != nil || size < 1 || size > 1048576 {
		fmt.Fprintln(os.Stderr, "invalid bytes")
		os.Exit(2)
	}
	if args[1] == "server" {
		err = server(args[2], net.JoinHostPort(args[3], args[4]), size, args[6])
	} else if args[1] == "load" && len(args) == 11 {
		values := make([]int, 4)
		for index := range values {
			values[index], err = strconv.Atoi(args[index+5])
			if err != nil {
				break
			}
		}
		if err == nil && (values[0] < 1 || values[0] > 128 || values[1] < 1 || values[1] > 200000 || values[2] < 0 || values[2] > 10000 || values[3] < 1 || values[3] > 60000) {
			err = fmt.Errorf("invalid load bounds")
		}
		if err == nil {
			var result sample
			result, err = load(net.JoinHostPort(args[2], args[3]), size, values[0], values[1], values[2], values[3], args[9], args[10])
			if err == nil {
				if err = json.NewEncoder(os.Stdout).Encode(result); err == nil {
					if result.Failed > 0 || result.WarmupFailed > 0 {
						os.Exit(1)
					}
					return
				}
			}
		}
	} else {
		err = fmt.Errorf("invalid command")
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
