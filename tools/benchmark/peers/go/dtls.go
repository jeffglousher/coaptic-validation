package main

// Independent bounded CoAP wire driver over authenticated Pion DTLS records.
// Each worker owns one warm DTLS session and one outstanding CoAP datagram.
import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

const dtlsSecurity = "DTLS1.2-PSK-AES128-CCM8"

func dtlsConfig(path string, client bool) (*dtls.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var material [25]byte
	n, err := io.ReadFull(file, material[:])
	if n != 24 || err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("expected 24-byte ephemeral credentials")
	}
	key := bytes.Clone(material[:16])
	clear(material[:])
	return &dtls.Config{
		PSK: func(identity []byte) ([]byte, error) {
			// A server's PSK identity hint is optional. The client still sends
			// its explicit identity and authenticates possession of this PSK.
			if !bytes.Equal(identity, []byte("benchmark")) && !(client && len(identity) == 0) {
				return nil, fmt.Errorf("unexpected DTLS identity")
			}
			return bytes.Clone(key), nil
		},
		PSKIdentityHint: []byte("benchmark"),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
	}, nil
}

type dtlsWorker struct {
	conn     *dtls.Conn
	retired  []*dtls.Conn
	config   *dtls.Config
	address  *net.UDPAddr
	mid      uint32
	wire     [65535]byte
	expected []byte
}

func (w *dtlsWorker) connect(timeout time.Duration) error {
	conn, err := dtls.Dial("udp4", w.address, w.config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return err
	}
	state, ok := conn.ConnectionState()
	if !ok || state.CipherSuiteID != dtls.TLS_PSK_WITH_AES_128_CCM_8 {
		_ = conn.Close()
		return fmt.Errorf("DTLS cipher mismatch")
	}
	if w.conn != nil {
		w.retired = append(w.retired, w.conn)
	}
	w.conn, w.mid = conn, 0
	return nil
}

func (w *dtlsWorker) close() {
	if w.conn != nil {
		_ = w.conn.Close()
	}
	for _, c := range w.retired {
		_ = c.Close()
	}
}

func coapRequest(mid uint16, token [8]byte, block *uint32, con bool, out *[32]byte) []byte {
	out[0] = 0x58
	if con {
		out[0] = 0x48
	}
	out[1] = 1
	binary.BigEndian.PutUint16(out[2:4], mid)
	copy(out[4:12], token[:])
	copy(out[12:18], []byte("\xb5bench"))
	n := 18
	if block != nil {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], *block)
		first := 0
		for first < 4 && raw[first] == 0 {
			first++
		}
		out[n] = 0xc0 | byte(4-first)
		n++
		n += copy(out[n:], raw[first:])
	}
	return out[:n]
}

type coapReply struct {
	body, etag []byte
	block      *uint32
}

func optionExtended(raw byte, wire []byte, cursor *int) (int, error) {
	switch raw {
	case 13:
		if *cursor >= len(wire) {
			return 0, fmt.Errorf("short option")
		}
		n := 13 + int(wire[*cursor])
		*cursor++
		return n, nil
	case 14:
		if *cursor+2 > len(wire) {
			return 0, fmt.Errorf("short option")
		}
		n := 269 + int(binary.BigEndian.Uint16(wire[*cursor:*cursor+2]))
		*cursor += 2
		return n, nil
	case 15:
		return 0, fmt.Errorf("reserved option")
	default:
		return int(raw), nil
	}
}

func decodeCoap(wire []byte, token [8]byte) (coapReply, error) {
	var reply coapReply
	if len(wire) < 12 || wire[0]>>6 != 1 || wire[0]&15 != 8 || wire[1] != 69 || !bytes.Equal(wire[4:12], token[:]) {
		return reply, fmt.Errorf("response status/header/token")
	}
	cursor, number, format := 12, 0, false
	for cursor < len(wire) && wire[cursor] != 255 {
		header := wire[cursor]
		cursor++
		delta, err := optionExtended(header>>4, wire, &cursor)
		if err != nil {
			return reply, err
		}
		length, err := optionExtended(header&15, wire, &cursor)
		if err != nil {
			return reply, err
		}
		number += delta
		if number > 65535 || cursor+length > len(wire) {
			return reply, fmt.Errorf("option bounds")
		}
		value := wire[cursor : cursor+length]
		cursor += length
		switch number {
		case 4:
			if reply.etag != nil || len(value) == 0 || len(value) > 8 {
				return reply, fmt.Errorf("ETag")
			}
			reply.etag = value
		case 12:
			if format || len(value) > 2 {
				return reply, fmt.Errorf("Content-Format")
			}
			var n uint32
			for _, b := range value {
				n = n<<8 | uint32(b)
			}
			if n != 42 {
				return reply, fmt.Errorf("Content-Format")
			}
			format = true
		case 23:
			if reply.block != nil || len(value) > 3 {
				return reply, fmt.Errorf("Block2")
			}
			var n uint32
			for _, b := range value {
				n = n<<8 | uint32(b)
			}
			if n&7 == 7 {
				return reply, fmt.Errorf("BERT on UDP")
			}
			reply.block = &n
		case 14, 28:
		default:
			if number&1 != 0 {
				return reply, fmt.Errorf("unsupported critical option")
			}
		}
	}
	if cursor < len(wire) {
		reply.body = wire[cursor+1:]
	}
	if !format || len(reply.body) == 0 {
		return reply, fmt.Errorf("missing format/body")
	}
	return reply, nil
}

func (w *dtlsWorker) exchange(worker int, sequence uint64, con bool, timeout time.Duration) (int64, error) {
	started := stamp()
	deadline := time.Now().Add(timeout)
	// Reserve the legal 16-byte-block worst case without ever reusing a MID
	// on a live endpoint. Rotation remains inside the complete-operation clock.
	if w.mid+uint32((len(w.expected)+15)/16) > 65536 {
		if len(w.retired) >= 1023 {
			return 0, fmt.Errorf("driver endpoint limit")
		}
		if err := w.connect(time.Until(deadline)); err != nil {
			return 0, fmt.Errorf("driver endpoint rotation: %w", err)
		}
	}
	if err := w.conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	var token [8]byte
	binary.BigEndian.PutUint64(token[:], uint64(worker)<<48|sequence)
	var requested *uint32
	if len(w.expected) > 1024 {
		n := uint32(6)
		requested = &n
	}
	offset := 0
	var expectedETag [8]byte
	etagLength := -1
	seen := false
	for {
		if !time.Now().Before(deadline) {
			return 0, fmt.Errorf("complete-operation deadline")
		}
		mid := uint16(w.mid)
		w.mid++
		var encoded [32]byte
		if _, err := w.conn.Write(coapRequest(mid, token, requested, con, &encoded)); err != nil {
			return 0, err
		}
		var reply coapReply
		for {
			if !time.Now().Before(deadline) {
				return 0, fmt.Errorf("complete-operation deadline")
			}
			n, err := w.conn.Read(w.wire[:])
			if err != nil {
				return 0, err
			}
			wire := w.wire[:n]
			if len(wire) == 4 && bytes.Equal(wire, []byte{0x60, 0, byte(mid >> 8), byte(mid)}) {
				if !con {
					return 0, fmt.Errorf("ACK for NON")
				}
				continue
			}
			if n < 12 || !bytes.Equal(wire[4:12], token[:]) {
				continue
			}
			ty := wire[0] >> 4 & 3
			if ty == 3 || (ty == 2 && !con) {
				return 0, fmt.Errorf("response type")
			}
			if ty == 2 && binary.BigEndian.Uint16(wire[2:4]) != mid {
				continue
			}
			reply, err = decodeCoap(wire, token)
			if err != nil {
				return 0, err
			}
			if ty == 0 {
				if _, err = w.conn.Write([]byte{0x60, 0, wire[2], wire[3]}); err != nil {
					return 0, err
				}
			}
			break
		}
		l := -1
		if reply.etag != nil {
			l = len(reply.etag)
		}
		if seen && (l != etagLength || (l >= 0 && !bytes.Equal(reply.etag, expectedETag[:l]))) {
			return 0, fmt.Errorf("changed ETag")
		}
		etagLength = l
		copy(expectedETag[:], reply.etag)
		seen = true
		if offset+len(reply.body) > len(w.expected) || !bytes.Equal(reply.body, w.expected[offset:offset+len(reply.body)]) {
			return 0, fmt.Errorf("complete representation mismatch")
		}
		end := offset + len(reply.body)
		if reply.block == nil {
			if requested != nil || offset != 0 || end != len(w.expected) {
				return 0, fmt.Errorf("missing negotiated Block2")
			}
			return stamp() - started, nil
		}
		block := *reply.block
		size := 1 << ((block & 7) + 4)
		more := block&8 != 0
		if requested != nil && block&7 > *requested&7 {
			return 0, fmt.Errorf("Block2 size increased")
		}
		if int(block>>4)*size != offset || len(reply.body) > size || (more && (len(reply.body) != size || end >= len(w.expected))) {
			return 0, fmt.Errorf("Block2 range/M/length")
		}
		offset = end
		if !more {
			if offset != len(w.expected) {
				return 0, fmt.Errorf("incomplete representation")
			}
			return stamp() - started, nil
		}
		next := uint32(offset/size)<<4 | block&7
		requested = &next
	}
}

func dtlsEndpointBound(size, concurrency, operations, warmup int) int {
	perEndpoint := 65536 / ((size + 15) / 16)
	total := 0
	for worker := 0; worker < concurrency; worker++ {
		calls := operations/concurrency + warmup
		if worker < operations%concurrency {
			calls++
		}
		count := (calls + perEndpoint - 1) / perEndpoint
		if count < 1 {
			count = 1
		}
		total += count
	}
	return total
}

func dtlsLoadCommand(args []string) error {
	if len(args) != 11 {
		return fmt.Errorf("dtls-load HOST PORT BYTES CONCURRENCY OPERATIONS WARMUP TIMEOUT_MS con|non CREDENTIALS")
	}
	if args[2] != "127.0.0.1" {
		return fmt.Errorf("DTLS fixture is loopback only")
	}
	values := make([]int, 6)
	for i := range values {
		n, err := strconv.Atoi(args[i+3])
		if err != nil {
			return err
		}
		values[i] = n
	}
	port, size, concurrency, operations, warmup, timeoutMS := values[0], values[1], values[2], values[3], values[4], values[5]
	if port < 1 || port > 65535 || size < 1 || size > 1048576 || concurrency < 1 || concurrency > 128 || operations < 1 || operations > 200000 || warmup < 0 || warmup > 10000 || timeoutMS < 1 || timeoutMS > 60000 || (args[9] != "con" && args[9] != "non") {
		return fmt.Errorf("DTLS load bounds")
	}
	if dtlsEndpointBound(size, concurrency, operations, warmup) > 1024 {
		return fmt.Errorf("driver endpoint reservation exceeds1024")
	}
	config, err := dtlsConfig(args[10], true)
	if err != nil {
		return err
	}
	expected := payload(size)
	timeout := time.Duration(timeoutMS) * time.Millisecond
	workers := make([]*dtlsWorker, 0, concurrency)
	defer func() {
		for _, w := range workers {
			w.close()
		}
	}()
	for i := 0; i < concurrency; i++ {
		w := &dtlsWorker{config: config, address: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, expected: expected}
		if err := w.connect(timeout); err != nil {
			return err
		}
		workers = append(workers, w)
	}
	result := sample{Schema: "coaptic-load/1", Protocol: "coap", Security: dtlsSecurity, Mode: args[9], Concurrency: concurrency, Warmup: warmup, Attempted: operations, Clock: clockName, ClockResolutionNS: clockResolutionNS, Latencies: make([]int64, 0, operations), Measurement: "closed-loop complete authenticated CoAP over DTLS; initial session handshakes/setup excluded; rotation included; complete body/status/format/ETag/Block2 verification included; no CoAP retransmission"}
	var ready, finished sync.WaitGroup
	var mutex sync.Mutex
	ready.Add(concurrency)
	finished.Add(concurrency)
	start := make(chan struct{})
	for i, w := range workers {
		go func(i int, w *dtlsWorker) {
			defer finished.Done()
			sequence := uint64(1)
			warmupFailed := 0
			for n := 0; n < warmup; n++ {
				if _, err := w.exchange(i, sequence, args[9] == "con", timeout); err != nil {
					warmupFailed++
				}
				sequence++
			}
			count := operations / concurrency
			if i < operations%concurrency {
				count++
			}
			local := make([]int64, 0, count)
			failed, driverFailed := 0, 0
			mutex.Lock()
			result.WarmupFailed += warmupFailed
			mutex.Unlock()
			ready.Done()
			<-start
			for n := 0; n < count; n++ {
				elapsed, err := w.exchange(i, sequence, args[9] == "con", timeout)
				sequence++
				if err != nil {
					failed++
					if strings.HasPrefix(err.Error(), "driver ") {
						driverFailed++
					}
				} else {
					local = append(local, elapsed)
				}
			}
			mutex.Lock()
			result.Latencies = append(result.Latencies, local...)
			result.Failed += failed
			result.DriverFailures += driverFailed
			result.EndpointRotations += len(w.retired)
			mutex.Unlock()
		}(i, w)
	}
	ready.Wait()
	started := stamp()
	close(start)
	finished.Wait()
	result.ElapsedNS = stamp() - started
	result.Completed = len(result.Latencies)
	result.VerifiedBytes = result.Completed * size
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if result.Failed != 0 || result.WarmupFailed != 0 {
		os.Exit(1)
	}
	return nil
}
