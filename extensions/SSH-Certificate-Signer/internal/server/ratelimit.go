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
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/apache/airavata-custos/signer/internal/httputil"
	"github.com/apache/airavata-custos/signer/internal/metrics"
)

// TrustedProxies is a set of CIDR ranges whose X-Forwarded-For header may be
// trusted. Any peer outside these ranges is treated as a direct, potentially
// hostile client whose XFF header is ignored.
type TrustedProxies struct {
	nets []*net.IPNet
}

// ParseTrustedProxies builds a TrustedProxies from CIDR strings or bare IPs
// ("10.0.0.0/8", "192.168.1.1"). Malformed entries are skipped and reported in
// the returned error so callers can log them; the returned set still contains
// every entry that parsed cleanly (fail-closed: an unparseable proxy is simply
// not trusted).
func ParseTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	tp := &TrustedProxies{}
	var bad []string
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Accept a bare IP by widening it to a single-host CIDR.
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					c += "/32"
				} else {
					c += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			bad = append(bad, c)
			continue
		}
		tp.nets = append(tp.nets, n)
	}
	if len(bad) > 0 {
		return tp, fmt.Errorf("ignored malformed trusted_proxies entries: %s", strings.Join(bad, ", "))
	}
	return tp, nil
}

// Contains reports whether ip falls inside any trusted range.
func (tp *TrustedProxies) Contains(ip net.IP) bool {
	if tp == nil || ip == nil {
		return false
	}
	for _, n := range tp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hostFromRemoteAddr strips the port from a "host:port" address, handling
// bracketed IPv6 literals. It returns the input unchanged if it has no port.
func hostFromRemoteAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// clientIP determines the trustworthy source IP for r.
//
// The X-Forwarded-For header is attacker-controlled: any client can set it to
// an arbitrary value. It is therefore only consulted when the immediate peer
// (r.RemoteAddr) is a configured trusted proxy. In that case we walk the header
// from right to left — the rightmost entries are appended by infrastructure we
// control — and return the first address that is not itself a trusted proxy,
// i.e. the real originating client. When the peer is not trusted, the header is
// ignored entirely and the peer address is used.
func clientIP(r *http.Request, trusted *TrustedProxies) string {
	peer := hostFromRemoteAddr(r.RemoteAddr)
	if !trusted.Contains(net.ParseIP(peer)) {
		return peer
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if !trusted.Contains(parsed) {
			return ip
		}
	}
	return peer
}

// RateLimiter throttles requests per key (source IP) using an independent token
// bucket for each key. Buckets are created lazily on first use and evicted once
// they have been idle longer than ttl, so memory usage tracks the number of
// *active* clients rather than the total ever seen.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rlBucket
	rps     rate.Limit
	burst   int
	ttl     time.Duration
}

type rlBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter returns a limiter allowing rps sustained requests per second
// per key, tolerating bursts of up to burst requests. Buckets idle for longer
// than ttl are reclaimed by the reaper started via StartReaper.
func NewRateLimiter(rps float64, burst int, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*rlBucket),
		rps:     rate.Limit(rps),
		burst:   burst,
		ttl:     ttl,
	}
}

// Allow records activity for key and reports whether a request is permitted.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	b, ok := rl.buckets[key]
	if !ok {
		b = &rlBucket{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.buckets[key] = b
	}
	b.lastSeen = time.Now()
	rl.mu.Unlock()
	return b.limiter.Allow()
}

// reap removes every bucket last seen before cutoff and returns how many were
// evicted. Exposed for deterministic testing of the eviction path.
func (rl *RateLimiter) reap(cutoff time.Time) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	removed := 0
	for k, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, k)
			removed++
		}
	}
	return removed
}

// size returns the current number of tracked buckets.
func (rl *RateLimiter) size() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// StartReaper launches a background goroutine that periodically evicts idle
// buckets until ctx is cancelled.
func (rl *RateLimiter) StartReaper(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				rl.reap(now.Add(-rl.ttl))
			}
		}
	}()
}

// Middleware rejects requests from any source IP that has exhausted its bucket
// with HTTP 429 and a Retry-After hint, incrementing the rate-limit metric.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := httputil.SourceIPFromContext(r.Context())
		if key == "" {
			key = hostFromRemoteAddr(r.RemoteAddr)
		}
		if !rl.Allow(key) {
			metrics.RateLimitedRequestsTotal.Inc()
			w.Header().Set("Retry-After", "1")
			httputil.WriteJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}
