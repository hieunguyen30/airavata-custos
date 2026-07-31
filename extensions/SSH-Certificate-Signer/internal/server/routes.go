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
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/apache/airavata-custos/signer/internal/auth"
	"github.com/apache/airavata-custos/signer/internal/config"
)

type Handlers struct {
	Sign              http.HandlerFunc
	Revoke            http.HandlerFunc
	JWKS              http.HandlerFunc
	CAPublicKey       http.HandlerFunc
	Health            http.HandlerFunc
	Admin             http.HandlerFunc
	Certificates      http.HandlerFunc
	CertificateDetail http.HandlerFunc
	UserInfo          http.HandlerFunc
}

func NewRouter(
	cfg *config.Config,
	authenticator *auth.ClientAuthenticator,
	oidcValidator *auth.OIDCValidator,
	handlers Handlers,
) *chi.Mux {
	r := chi.NewRouter()

	trusted, err := ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		// Malformed entries are dropped, not fatal: the unparseable proxy is
		// simply never trusted. Log so operators can fix the config.
		slog.Warn("trusted_proxies contained invalid entries", "error", err)
	}

	// A single limiter is shared across every authenticated endpoint so a
	// client's budget covers all of its requests, not one bucket per route.
	var rateLimiter *RateLimiter
	if cfg.RateLimit.Enabled {
		ttl := time.Duration(cfg.RateLimit.CleanupIntervalSeconds) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		rateLimiter = NewRateLimiter(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst, ttl)
		rateLimiter.StartReaper(context.Background(), ttl)
		slog.Info("per-client rate limiting enabled",
			"requests_per_second", cfg.RateLimit.RequestsPerSecond,
			"burst", cfg.RateLimit.Burst)
	}

	if cfg.CORS.Enabled {
		r.Use(CORSMiddleware(cfg.CORS))
	}
	r.Use(SecurityHeadersMiddleware)
	r.Use(SourceIPMiddleware(trusted))
	r.Use(BodyLimitMiddleware(1 << 20)) // 1 MB

	// Health endpoint (no auth, exempt from rate limiting for load-balancer probes)
	r.Get("/api/v1/health", handlers.Health)

	// Metrics endpoint (no auth, exempt from rate limiting)
	if cfg.Metrics.Enabled {
		r.Handle(cfg.Metrics.Path, promhttp.Handler())
	}

	// Client-authenticated routes (machine-to-machine).
	// Rate limiting runs before authentication so floods are rejected before
	// any credential lookup or cryptographic work.
	r.Group(func(r chi.Router) {
		if rateLimiter != nil {
			r.Use(rateLimiter.Middleware)
		}
		r.Use(ClientAuthMiddleware(authenticator))

		r.Post("/api/v1/sign", handlers.Sign)
		r.Post("/api/v1/revoke", handlers.Revoke)
		r.Get("/api/v1/jwks", handlers.JWKS)
		r.Get("/api/v1/ca-public-key", handlers.CAPublicKey)
		r.Post("/api/v1/admin/rotate-ca", handlers.Admin)
	})

	// User-authenticated routes (OIDC Bearer token)
	r.Group(func(r chi.Router) {
		if rateLimiter != nil {
			r.Use(rateLimiter.Middleware)
		}
		r.Use(BearerAuthMiddleware(oidcValidator))

		r.Get("/api/v1/certificates", handlers.Certificates)
		r.Get("/api/v1/certificates/{serial}", handlers.CertificateDetail)
		r.Get("/api/v1/userinfo", handlers.UserInfo)
	})

	return r
}
