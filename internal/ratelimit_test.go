package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func tightLimiter() *ipLimiter {
	return newIPLimiter(5, time.Minute, 3, 10*time.Millisecond)
}

func TestIPLimiter_AllowsWithinLimit(t *testing.T) {
	l := tightLimiter()
	for i := 0; i < 5; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("allow returned false on request %d (within limit)", i+1)
		}
	}
}

func TestIPLimiter_DeniesOverLimit(t *testing.T) {
	l := tightLimiter()
	for i := 0; i < 5; i++ {
		l.allow("1.2.3.4")
	}
	if l.allow("1.2.3.4") {
		t.Error("allow returned true over limit, want false")
	}
}

func TestIPLimiter_LocksOutAfterMaxFailures(t *testing.T) {
	l := tightLimiter() // maxFail = 3
	l.failure("1.2.3.4")
	l.failure("1.2.3.4")
	if !l.allow("1.2.3.4") {
		t.Error("should not be locked after 2 failures")
	}
	l.failure("1.2.3.4") // 3rd → lockout
	if l.allow("1.2.3.4") {
		t.Error("should be locked after 3 failures")
	}
}

func TestIPLimiter_SuccessResetsFailCount(t *testing.T) {
	l := tightLimiter()
	l.failure("1.2.3.4")
	l.failure("1.2.3.4")
	l.success("1.2.3.4")
	l.failure("1.2.3.4")
	l.failure("1.2.3.4")
	if !l.allow("1.2.3.4") {
		t.Error("should not be locked when fail count was reset by success")
	}
}

func TestIPLimiter_LockoutExpiresAfterDuration(t *testing.T) {
	l := tightLimiter() // lockout = 10ms
	l.failure("1.2.3.4")
	l.failure("1.2.3.4")
	l.failure("1.2.3.4")
	if l.allow("1.2.3.4") {
		t.Error("should be locked immediately after failures")
	}
	time.Sleep(15 * time.Millisecond)
	if !l.allow("1.2.3.4") {
		t.Error("should be unlocked after lockout expires")
	}
}

func TestIPLimiter_IsolatesIPs(t *testing.T) {
	l := tightLimiter()
	l.failure("1.2.3.4")
	l.failure("1.2.3.4")
	l.failure("1.2.3.4")
	if !l.allow("5.6.7.8") {
		t.Error("5.6.7.8 should be unaffected by 1.2.3.4 lockout")
	}
}

func TestIPLimiter_WindowResets(t *testing.T) {
	l := newIPLimiter(2, 10*time.Millisecond, 10, time.Minute)
	l.allow("1.2.3.4")
	l.allow("1.2.3.4")
	if l.allow("1.2.3.4") {
		t.Error("should be denied when over window limit")
	}
	time.Sleep(15 * time.Millisecond)
	if !l.allow("1.2.3.4") {
		t.Error("should be allowed after window resets")
	}
}

func TestClientIP_ExtractsHostFromRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := clientIP(req); got != "192.0.2.1" {
		t.Errorf("clientIP = %q, want 192.0.2.1", got)
	}
}

func TestClientIP_FallbackOnMalformedAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-an-addr"
	if got := clientIP(req); got != "not-an-addr" {
		t.Errorf("clientIP = %q, want not-an-addr", got)
	}
}
