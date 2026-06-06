package internal

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ipLimiter enforces per-IP request rate limits and failed-password lockout.
// Two independent mechanisms:
//   - Sliding-window request cap: more than maxReq requests in window → deny.
//   - Failure lockout: maxFail consecutive bad passwords → lockout for lockout duration.
type ipLimiter struct {
	mu      sync.Mutex
	ips     map[string]*ipState
	maxReq  int
	window  time.Duration
	maxFail int
	lockout time.Duration
}

type ipState struct {
	windowStart time.Time
	reqCount    int
	failCount   int
	lockedUntil time.Time
}

func newIPLimiter(maxReq int, window time.Duration, maxFail int, lockout time.Duration) *ipLimiter {
	return &ipLimiter{
		ips:     make(map[string]*ipState),
		maxReq:  maxReq,
		window:  window,
		maxFail: maxFail,
		lockout: lockout,
	}
}

// allow returns true if the request from ip is within limits and not locked out.
func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.getOrCreate(ip)
	now := time.Now()

	if now.Before(s.lockedUntil) {
		return false
	}
	if now.Sub(s.windowStart) >= l.window {
		s.windowStart = now
		s.reqCount = 0
	}
	s.reqCount++
	return s.reqCount <= l.maxReq
}

// failure records a failed authentication attempt. After maxFail consecutive
// failures the IP is locked out for the lockout duration.
func (l *ipLimiter) failure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.getOrCreate(ip)
	s.failCount++
	if s.failCount >= l.maxFail {
		s.lockedUntil = time.Now().Add(l.lockout)
		s.failCount = 0
	}
}

// success resets the consecutive failure counter for ip.
func (l *ipLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if s, ok := l.ips[ip]; ok {
		s.failCount = 0
	}
}

func (l *ipLimiter) getOrCreate(ip string) *ipState {
	s, ok := l.ips[ip]
	if !ok {
		s = &ipState{windowStart: time.Now()}
		l.ips[ip] = s
	}
	return s
}

// clientIP extracts the client IP address from r.RemoteAddr (strips port).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
