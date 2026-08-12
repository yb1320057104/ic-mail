package app

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type loginAttempt struct {
	failures  []time.Time
	blockedTo time.Time
}

type loginGuard struct {
	mu            sync.Mutex
	byIP          map[string]*loginAttempt
	byUsername    map[string]*loginAttempt
	window        time.Duration
	ipLimit       int
	usernameLimit int
	maxBackoff    time.Duration
	now           func() time.Time
}

type requestRateLimiter struct {
	mu          sync.Mutex
	byIP        map[string][]time.Time
	byResource  map[string][]time.Time
	window      time.Duration
	ipLimit     int
	resourceMax int
}

func newRequestRateLimiter(window time.Duration, ipLimit, resourceMax int) *requestRateLimiter {
	return &requestRateLimiter{byIP: map[string][]time.Time{}, byResource: map[string][]time.Time{}, window: window, ipLimit: ipLimit, resourceMax: resourceMax}
}

func (l *requestRateLimiter) allow(ip, resource string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	check := func(entries map[string][]time.Time, key string, limit int) (bool, time.Duration) {
		cutoff := now.Add(-l.window)
		rows := entries[key][:0]
		for _, at := range entries[key] {
			if at.After(cutoff) {
				rows = append(rows, at)
			}
		}
		if len(rows) >= limit {
			entries[key] = rows
			return false, max(time.Second, rows[0].Add(l.window).Sub(now))
		}
		entries[key] = append(rows, now)
		return true, 0
	}
	if ok, retry := check(l.byIP, ip, l.ipLimit); !ok {
		return false, retry
	}
	if ok, retry := check(l.byResource, ip+"|"+resource, l.resourceMax); !ok {
		// The IP counter already recorded this rejected attempt; this is intentional
		// so rotating mailbox IDs cannot bypass the global IP ceiling.
		return false, retry
	}
	return true, 0
}

func newLoginGuard(cfg Config) *loginGuard {
	if cfg.LoginRateLimitWindowSeconds <= 0 {
		cfg.LoginRateLimitWindowSeconds = 600
	}
	if cfg.LoginRateLimitPerIP <= 0 {
		cfg.LoginRateLimitPerIP = 5
	}
	if cfg.LoginRateLimitPerUsername <= 0 {
		cfg.LoginRateLimitPerUsername = 5
	}
	if cfg.LoginBackoffMaxSeconds <= 0 {
		cfg.LoginBackoffMaxSeconds = 600
	}
	return &loginGuard{
		byIP: make(map[string]*loginAttempt), byUsername: make(map[string]*loginAttempt),
		window:  time.Duration(cfg.LoginRateLimitWindowSeconds) * time.Second,
		ipLimit: cfg.LoginRateLimitPerIP, usernameLimit: cfg.LoginRateLimitPerUsername,
		maxBackoff: time.Duration(cfg.LoginBackoffMaxSeconds) * time.Second, now: time.Now,
	}
}

func (g *loginGuard) allow(ip, username string) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var retry time.Duration
	for _, item := range []struct {
		key     string
		entries map[string]*loginAttempt
		limit   int
	}{
		{ip, g.byIP, g.ipLimit}, {normalizeUsername(username), g.byUsername, g.usernameLimit},
	} {
		if item.key == "" {
			continue
		}
		a := g.prune(item.entries, item.key, now)
		if a.blockedTo.After(now) || len(a.failures) >= item.limit {
			wait := a.blockedTo.Sub(now)
			if wait <= 0 {
				wait = time.Second
			}
			if wait > retry {
				retry = wait
			}
		}
	}
	return retry <= 0, retry
}

func (g *loginGuard) failure(ip, username string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var retry time.Duration
	for _, item := range []struct {
		key     string
		entries map[string]*loginAttempt
		limit   int
	}{
		{ip, g.byIP, g.ipLimit}, {normalizeUsername(username), g.byUsername, g.usernameLimit},
	} {
		if item.key == "" {
			continue
		}
		a := g.prune(item.entries, item.key, now)
		a.failures = append(a.failures, now)
		if len(a.failures) >= item.limit {
			backoff := g.maxBackoff
			a.blockedTo = now.Add(backoff)
			if backoff > retry {
				retry = backoff
			}
		}
	}
	return retry
}

func (g *loginGuard) success(ip, username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.byUsername, normalizeUsername(username))
	// Keep the IP history so one successful account cannot reset an attacking IP.
	if a := g.byIP[ip]; a != nil {
		a.blockedTo = time.Time{}
	}
}

func (g *loginGuard) prune(entries map[string]*loginAttempt, key string, now time.Time) *loginAttempt {
	a := entries[key]
	if a == nil {
		a = &loginAttempt{}
		entries[key] = a
	}
	cutoff := now.Add(-g.window)
	kept := a.failures[:0]
	for _, at := range a.failures {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	a.failures = kept
	if len(kept) == 0 && !a.blockedTo.After(now) {
		a.blockedTo = time.Time{}
	}
	return a
}

func requestClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	parsed := net.ParseIP(host)
	// Forwarded headers are trusted only from a loopback reverse proxy.
	if parsed != nil && parsed.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(realIP) != nil {
			return realIP
		}
	}
	return host
}

func writeRateLimit(w http.ResponseWriter, retry time.Duration) {
	seconds := int(retry.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, http.StatusTooManyRequests, errCode("login_rate_limited", "登录尝试过于频繁，请稍后重试", true))
}
