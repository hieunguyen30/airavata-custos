// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiter_BurstThenThrottle(t *testing.T) {
	rl := NewRateLimiter(10, 5, time.Minute)

	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Error("request beyond burst should be throttled")
	}
}

func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute)

	if !rl.Allow("client-a") {
		t.Fatal("client-a first request should be allowed")
	}
	// client-a is now exhausted, but client-b has its own bucket.
	if !rl.Allow("client-b") {
		t.Error("client-b must not be throttled by client-a's usage")
	}
	if rl.Allow("client-a") {
		t.Error("client-a second request should be throttled")
	}
}

func TestRateLimiter_ReapEvictsIdleBuckets(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute)
	rl.Allow("stale")
	if rl.size() != 1 {
		t.Fatalf("expected 1 bucket, got %d", rl.size())
	}
	// Evict everything last seen before "now + 1h" — i.e. all of it.
	removed := rl.reap(time.Now().Add(time.Hour))
	if removed != 1 {
		t.Errorf("expected 1 bucket evicted, got %d", removed)
	}
	if rl.size() != 0 {
		t.Errorf("expected 0 buckets after reap, got %d", rl.size())
	}
}

func TestRateLimiter_Middleware429(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute)
	handler := SourceIPMiddleware(nil)(rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	newReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/sign", nil)
		req.RemoteAddr = "198.51.100.7:9999"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := newReq(); rec.Code != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", rec.Code)
	}
	rec := newReq()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 response should carry a Retry-After header")
	}
}

func TestParseTrustedProxies_ReportsBadEntries(t *testing.T) {
	tp, err := ParseTrustedProxies([]string{"10.0.0.0/8", "not-an-ip", "192.168.1.1"})
	if err == nil {
		t.Error("expected an error reporting the malformed entry")
	}
	// Valid entries must still be usable despite the bad one.
	if !tp.Contains(net.ParseIP("10.1.1.1")) {
		t.Error("10.0.0.0/8 should still be trusted")
	}
	if !tp.Contains(net.ParseIP("192.168.1.1")) {
		t.Error("bare IP 192.168.1.1 should be trusted")
	}
}

// --- Load test -------------------------------------------------------------
//
// TestRateLimiter_LoadProfile drives the rate-limiting middleware over real
// HTTP from many concurrent goroutines and reports the numbers that back the
// résumé claim: sustained throughput cap, share of flood traffic rejected with
// 429, and added per-request latency. Run with:
//
//	go test ./internal/server/ -run LoadProfile -v
func TestRateLimiter_LoadProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in -short mode")
	}

	const (
		rps      = 1000.0
		burst    = 1000
		workers  = 50
		duration = 2 * time.Second
	)

	rl := NewRateLimiter(rps, burst, time.Minute)
	limited := httptest.NewServer(SourceIPMiddleware(nil)(rl.Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)))
	defer limited.Close()

	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: workers}}

	var allowed, throttled int64
	var mu sync.Mutex
	var latencies []time.Duration

	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(duration)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				resp, err := client.Get(limited.URL)
				lat := time.Since(t0)
				if err != nil {
					continue
				}
				resp.Body.Close()
				local = append(local, lat)
				if resp.StatusCode == http.StatusTooManyRequests {
					atomic.AddInt64(&throttled, 1)
				} else {
					atomic.AddInt64(&allowed, 1)
				}
			}
			mu.Lock()
			latencies = append(latencies, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := allowed + throttled
	theoreticalCap := float64(burst) + rps*elapsed.Seconds()
	avg, p99 := latencyStats(latencies)

	t.Logf("=== Rate-limiter load profile (single source IP) ===")
	t.Logf("duration:            %v", elapsed.Round(time.Millisecond))
	t.Logf("total requests:      %d (%.0f req/s offered)", total, float64(total)/elapsed.Seconds())
	t.Logf("allowed (200):       %d (%.0f req/s sustained)", allowed, float64(allowed)/elapsed.Seconds())
	t.Logf("throttled (429):     %d (%.1f%% of flood rejected)", throttled, 100*float64(throttled)/float64(total))
	t.Logf("configured cap:      %.0f req/s, burst %d", rps, burst)
	t.Logf("theoretical ceiling: ~%.0f allowed over window", theoreticalCap)
	t.Logf("latency avg / p99:   %v / %v", avg.Round(time.Microsecond), p99.Round(time.Microsecond))

	if throttled == 0 {
		t.Error("expected the limiter to reject flood traffic, but nothing was throttled")
	}
	if float64(allowed) > theoreticalCap*1.5 {
		t.Errorf("allowed count %d far exceeds the ~%.0f ceiling; cap not enforced", allowed, theoreticalCap)
	}
}

// BenchmarkRateLimiter_Allow measures the per-request cost of the limiter check
// itself, isolated from HTTP overhead — the honest "added latency" figure.
func BenchmarkRateLimiter_Allow(b *testing.B) {
	rl := NewRateLimiter(1e9, 1e9, time.Minute) // effectively unlimited: measure the fast path
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("192.0.2.1")
	}
}

func latencyStats(ds []time.Duration) (avg, p99 time.Duration) {
	if len(ds) == 0 {
		return 0, 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	avg = sum / time.Duration(len(ds))
	sorted := make([]time.Duration, len(ds))
	copy(sorted, ds)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)) * 0.99)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return avg, sorted[idx]
}
