// loadgen: a low-memory replacement for bench/load.js (same user loop, same think times).
//
// Virtual users are small state machines, not goroutines. A sleeping user is one entry in a timer
// heap; when it is due, one of a fixed pool of workers performs its next step (one request or two)
// on the user's own keep-alive connection, with read/write buffers owned by the worker. Memory per
// user is the struct plus its socket, about 1 KB, so a few hundred thousand users fit in a few
// hundred MB.
//
// Latency = request write -> full response read (like k6's http_req_duration, which excludes
// connecting). Failed = network error or status >= 400. "lag" is how late due users were picked up;
// if it grows, the generator itself is the bottleneck and the numbers are not about the server.
package main

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type token struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

const bucketUs = 100 // histogram resolution: 0.1 ms
const nBuckets = 600000

type stats struct {
	hist        []atomic.Uint64
	reqs, fails atomic.Uint64
	max         atomic.Int64
}

func newStats() *stats { return &stats{hist: make([]atomic.Uint64, nBuckets)} }

func (s *stats) add(d time.Duration, failed bool) {
	us := d.Microseconds()
	b := us / bucketUs
	if b >= nBuckets {
		b = nBuckets - 1
	}
	s.hist[b].Add(1)
	s.reqs.Add(1)
	if failed {
		s.fails.Add(1)
	}
	for {
		m := s.max.Load()
		if us <= m || s.max.CompareAndSwap(m, us) {
			break
		}
	}
}

func (s *stats) pct(p float64) float64 {
	total := s.reqs.Load()
	want := uint64(float64(total) * p)
	var acc uint64
	for i := range s.hist {
		acc += s.hist[i].Load()
		if acc > want {
			return float64((i+1)*bucketUs) / 1000
		}
	}
	return 0
}

var (
	addr     = flag.String("addr", "asmsrv:80", "server host:port")
	vus      = flag.Int("vus", 1000, "virtual users")
	vuOffset = flag.Int("vu-offset", 0, "first VU number - 1 (to split users across generators)")
	ramp     = flag.Duration("ramp", 60*time.Second, "ramp-up")
	hold     = flag.Duration("hold", 5*time.Minute, "hold at full load")
	tokPath  = flag.String("tokens", "seed/tokens.json", "tokens.json")
	srcAddr  = flag.String("src", "", "local IP to connect from (e.g. 127.0.0.2), to emulate one client machine per generator")
	workers  = flag.Int("workers", 1024, "worker goroutines (max requests in flight)")
)

var errCount, checkFails atomic.Uint64
var maxLagUs atomic.Int64

// vu is one virtual user: its connection and where it is in the loop.
type vu struct {
	id    int32
	state uint8 // 0 = load feed, 1 = open post, 2 = maybe like / maybe post
	iter  int32
	post  int64
	wake  int64 // unix nanos
	rng   uint64
	conn  net.Conn
}

func (v *vu) rand() float64 { // xorshift64*, per user, no shared lock
	v.rng ^= v.rng >> 12
	v.rng ^= v.rng << 25
	v.rng ^= v.rng >> 27
	return float64((v.rng*2685821657736338717)>>11) / (1 << 53)
}

func (v *vu) between(lo, hi float64) int64 { return int64((lo + v.rand()*(hi-lo)) * 1e9) }

// timer heap shard
type vheap []*vu

func (h vheap) Len() int           { return len(h) }
func (h vheap) Less(i, j int) bool { return h[i].wake < h[j].wake }
func (h vheap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *vheap) Push(x any)        { *h = append(*h, x.(*vu)) }
func (h *vheap) Pop() any          { o := *h; n := len(o); x := o[n-1]; *h = o[:n-1]; return x }

type shard struct {
	mu sync.Mutex
	h  vheap
}

var shards []*shard

func schedule(v *vu, after int64) {
	v.wake = time.Now().UnixNano() + after
	s := shards[int(v.id)%len(shards)]
	s.mu.Lock()
	heap.Push(&s.h, v)
	s.mu.Unlock()
}

// worker-owned buffers
type wbuf struct {
	rd  *bufio.Reader
	req []byte
	res []byte
}

var dialer net.Dialer

func doReq(v *vu, w *wbuf, method, path, auth string, body []byte) (int, []byte, error) {
	if v.conn == nil {
		c, err := dialer.Dial("tcp", *addr)
		if err != nil {
			return 0, nil, err
		}
		v.conn = c
	}
	b := w.req[:0]
	b = append(b, method...)
	b = append(b, ' ')
	b = append(b, path...)
	b = append(b, " HTTP/1.1\r\nHost: bench\r\nUser-Agent: loadgen\r\n"...)
	if auth != "" {
		b = append(b, "Authorization: Bearer "...)
		b = append(b, auth...)
		b = append(b, "\r\nContent-Type: application/json\r\n"...)
	}
	if method == "POST" {
		b = append(b, "Content-Length: "...)
		b = strconv.AppendInt(b, int64(len(body)), 10)
		b = append(b, "\r\n"...)
	}
	b = append(b, "\r\n"...)
	b = append(b, body...)
	w.req = b
	v.conn.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := v.conn.Write(b); err != nil {
		reset(v)
		return 0, nil, err
	}
	w.rd.Reset(v.conn)
	line, err := w.rd.ReadSlice('\n')
	if err != nil || len(line) < 12 {
		reset(v)
		return 0, nil, fmt.Errorf("status line: %v", err)
	}
	status, _ := strconv.Atoi(string(line[9:12]))
	clen := -1
	closeAfter := false
	for {
		h, err := w.rd.ReadSlice('\n')
		if err != nil {
			reset(v)
			return 0, nil, err
		}
		if len(h) <= 2 {
			break
		}
		if len(h) > 16 && bytes.EqualFold(h[:15], []byte("content-length:")) {
			clen, _ = strconv.Atoi(string(bytes.TrimSpace(h[15:])))
		} else if len(h) >= 17 && bytes.EqualFold(h[:17], []byte("connection: close")) {
			closeAfter = true
		}
	}
	if clen < 0 {
		reset(v)
		return 0, nil, fmt.Errorf("no content-length")
	}
	if cap(w.res) < clen {
		w.res = make([]byte, clen)
	}
	res := w.res[:clen]
	for n := 0; n < clen; {
		m, err := w.rd.Read(res[n:])
		n += m
		if err != nil && n < clen {
			reset(v)
			return 0, nil, err
		}
	}
	if w.rd.Buffered() != 0 { // the server never sends unasked bytes; anything else is a bug
		reset(v)
		return 0, nil, fmt.Errorf("unexpected extra bytes")
	}
	if closeAfter {
		reset(v)
	}
	return status, res, nil
}

func reset(v *vu) {
	if v.conn != nil {
		v.conn.Close()
		v.conn = nil
	}
}

func timed(st *stats, v *vu, w *wbuf, method, path, auth string, body []byte, ok func(int) bool) (int, []byte) {
	t := time.Now()
	status, resp, err := doReq(v, w, method, path, auth, body)
	st.add(time.Since(t), err != nil || status >= 400)
	if err != nil {
		if errCount.Add(1) <= 5 {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	} else if !ok(status) {
		checkFails.Add(1)
	}
	return status, resp
}

var idKey = []byte(`{"id":`)

// pickID returns a random post id from a feed body without a JSON decoder.
func pickID(v *vu, body []byte) (int64, bool) {
	var ids [32]int64
	n := 0
	for i := 0; n < len(ids); {
		j := bytes.Index(body[i:], idKey)
		if j < 0 {
			break
		}
		k := i + j + len(idKey)
		e := k
		for e < len(body) && body[e] >= '0' && body[e] <= '9' {
			e++
		}
		id, err := strconv.ParseInt(string(body[k:e]), 10, 64)
		if err == nil {
			ids[n] = id
			n++
		}
		i = e
	}
	if n == 0 {
		return 0, false
	}
	return ids[int(v.rand()*float64(n))], true
}

func step(st *stats, v *vu, w *wbuf, toks []token) {
	switch v.state {
	case 0:
		status, resp := timed(st, v, w, "GET", "/feed", "", nil, func(s int) bool { return s == 200 })
		id, ok := int64(0), false
		if status == 200 {
			id, ok = pickID(v, resp)
		}
		if !ok {
			schedule(v, v.between(3, 7))
			return
		}
		v.post = id
		v.state = 1
		schedule(v, v.between(3, 7))
	case 1:
		timed(st, v, w, "GET", "/posts/"+strconv.FormatInt(v.post, 10), "", nil, func(s int) bool { return s == 200 })
		v.state = 2
		schedule(v, v.between(3, 8))
	case 2:
		tok := toks[(int(v.id)-1)%len(toks)]
		if v.rand() < 0.15 {
			timed(st, v, w, "POST", "/posts/"+strconv.FormatInt(v.post, 10)+"/like", tok.Token, nil,
				func(s int) bool { return s == 200 || s == 201 })
		}
		if v.rand() < 0.02 {
			body, _ := json.Marshal(map[string]string{"body": fmt.Sprintf("%s says hi at %s (VU %d, iter %d)",
				tok.Username, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), v.id, v.iter)})
			timed(st, v, w, "POST", "/posts", tok.Token, body, func(s int) bool { return s == 201 })
		}
		v.iter++
		v.state = 0
		schedule(v, v.between(5, 15))
	}
}

func main() {
	flag.Parse()
	dialer = net.Dialer{Timeout: 30 * time.Second}
	if *srcAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(*srcAddr)}
		// Bind the address only and let connect() pick the port per destination
		// (IP_BIND_ADDRESS_NO_PORT). Without it, bind() hunts for a free port across every socket
		// on that address, which gets very expensive with tens of thousands of connections.
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 24, 1) })
			return serr
		}
	}
	raw, err := os.ReadFile(*tokPath)
	if err != nil {
		panic(err)
	}
	var toks []token
	if err := json.Unmarshal(raw, &toks); err != nil {
		panic(err)
	}
	st := newStats()
	ns := runtime.GOMAXPROCS(0)
	for i := 0; i < ns; i++ {
		shards = append(shards, &shard{})
	}
	due := make(chan *vu, *workers*4)
	var stopping atomic.Bool

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := &wbuf{rd: bufio.NewReaderSize(nil, 8192), req: make([]byte, 0, 1024), res: make([]byte, 0, 8192)}
			for v := range due {
				if stopping.Load() {
					reset(v)
					continue
				}
				step(st, v, w, toks)
			}
		}()
	}
	// dispatchers: one per shard, 1 ms resolution
	var dwg sync.WaitGroup
	for _, s := range shards {
		dwg.Add(1)
		go func(s *shard) {
			defer dwg.Done()
			tk := time.NewTicker(time.Millisecond)
			defer tk.Stop()
			for range tk.C {
				if stopping.Load() {
					return
				}
				now := time.Now().UnixNano()
				for {
					s.mu.Lock()
					if len(s.h) == 0 || s.h[0].wake > now {
						s.mu.Unlock()
						break
					}
					v := heap.Pop(&s.h).(*vu)
					s.mu.Unlock()
					if lag := (time.Now().UnixNano() - v.wake) / 1000; lag > maxLagUs.Load() {
						maxLagUs.Store(lag)
					}
					due <- v
				}
			}
		}(s)
	}

	start := time.Now()
	go func() {
		var lastReqs uint64
		for range time.Tick(10 * time.Second) {
			r := st.reqs.Load()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			fmt.Fprintf(os.Stderr, "[%4.0fs] reqs=%d (+%d/s) fails=%d p95=%.1fms p99=%.1fms max=%.0fms lag=%.0fms heap=%dMB\n",
				time.Since(start).Seconds(), r, (r-lastReqs)/10, st.fails.Load(), st.pct(0.95), st.pct(0.99),
				float64(st.max.Load())/1000, float64(maxLagUs.Swap(0))/1000, ms.HeapInuse>>20)
			lastReqs = r
		}
	}()
	// linear ramp: each user starts with load.js's first-iteration sleep of 0-5 s
	for i := 1; i <= *vus; i++ {
		n := *vuOffset + i
		v := &vu{id: int32(n), rng: uint64(n)*0x9E3779B97F4A7C15 | 1}
		schedule(v, v.between(0, 5))
		target := start.Add(time.Duration(float64(*ramp) * float64(i) / float64(*vus)))
		if d := time.Until(target); d > 0 {
			time.Sleep(d)
		}
	}
	time.Sleep(time.Until(start.Add(*ramp + *hold)))
	elapsed := time.Since(start)
	stopping.Store(true)
	dwg.Wait()
	close(due)
	wg.Wait()

	total := st.reqs.Load()
	fails := st.fails.Load()
	fmt.Printf("vus=%d reqs=%d rate=%.0f/s failed=%.3f%% (net errors %d, check fails %d)\n", *vus, total,
		float64(total)/elapsed.Seconds(), 100*float64(fails)/float64(max(total, 1)), errCount.Load(), checkFails.Load())
	fmt.Printf("latency ms: p50=%.1f p95=%.1f p99=%.1f max=%.1f\n", st.pct(0.50), st.pct(0.95), st.pct(0.99),
		float64(st.max.Load())/1000)
	pass := st.pct(0.95) < 500 && st.pct(0.99) < 1000 && float64(fails) < 0.01*float64(total)
	fmt.Printf("PASS=%v (p95<500ms, p99<1000ms, failed<1%%)\n", pass)
}
