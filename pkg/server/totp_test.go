package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
)

// rfc6238Secret is the SHA-1 test secret from RFC 6238 Appendix B,
// bytes 0x31..0x35 ("12345678901234567890").
var rfc6238Secret = []byte("12345678901234567890")

func newTOTPTestServer(t *testing.T, secret []byte) Server {
	t.Helper()
	return Server{
		DB:          newTestDB(),
		FileStore:   NewDatabaseFileStore(newTestDB()),
		MaxLength:   10000,
		MaxFileSize: 1024 * 1024,
		Registry:    prometheus.NewRegistry(),
		Logger:      zaptest.NewLogger(t),
		TOTPSecret:  secret,
	}
}

func resetTOTPRateLimits() {
	totpRates.mu.Lock()
	defer totpRates.mu.Unlock()
	totpRates.failures = make(map[string][]time.Time)
}

// --- ParseTOTPSecret ---

func TestParseTOTPSecret(t *testing.T) {
	raw := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of rfc6238Secret
	got, err := ParseTOTPSecret(raw)
	if err != nil {
		t.Fatalf("ParseTOTPSecret(%q): %v", raw, err)
	}
	if string(got) != string(rfc6238Secret) {
		t.Fatalf("decoded secret = %q, want %q", got, rfc6238Secret)
	}

	// Lowercase and separators must be tolerated (copied from provisioning tools).
	got2, err := ParseTOTPSecret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
	if err != nil || string(got2) != string(rfc6238Secret) {
		t.Fatalf("ParseTOTPSecret with separators: secret=%q err=%v", got2, err)
	}

	for _, bad := range []string{"", "ABCDEFG", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQO", "!!!!!!"} {
		if _, err := ParseTOTPSecret(bad); err == nil {
			t.Errorf("ParseTOTPSecret(%q) should fail", bad)
		}
	}
}

// --- RFC 6238 test vectors ---

func TestTOTPCode_RFC6238Vectors(t *testing.T) {
	// Values from RFC 6238 Appendix B, truncated to 6 digits.
	cases := []struct {
		counter int64
		want    string
	}{
		{1, "287082"},        // T=59
		{37037036, "081804"}, // T=1111111109
		{37037037, "050471"}, // T=1111111111
		{0, "755224"},        // T=0 (HOTP initial counter)
	}
	for _, c := range cases {
		if got := totpCode(rfc6238Secret, c.counter); got != c.want {
			t.Errorf("totpCode(counter=%d) = %s, want %s", c.counter, got, c.want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	resetTOTPRateLimits()

	now := time.Now().Unix() / totpStepSeconds
	good := totpCode(rfc6238Secret, now)
	if !verifyTOTP(rfc6238Secret, good) {
		t.Fatal("current code should verify")
	}
	// Skew: ±1 step accepted.
	if !verifyTOTP(rfc6238Secret, totpCode(rfc6238Secret, now+1)) {
		t.Fatal("+1 step code should verify")
	}
	if !verifyTOTP(rfc6238Secret, totpCode(rfc6238Secret, now-1)) {
		t.Fatal("-1 step code should verify")
	}

	// Same length and digits, but provably different from good: flip the
	// first digit.
	flip := byte('1')
	if good[0] == '1' {
		flip = '0'
	}
	for _, bad := range []string{"000000", "abcdef", "12345", "1234567", string(flip) + good[1:]} {
		if verifyTOTP(rfc6238Secret, bad) {
			t.Errorf("code %q should be rejected", bad)
		}
	}
}

// --- Cookie ---

func TestTOTPCookie(t *testing.T) {
	srv := newTOTPTestServer(t, rfc6238Secret)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if srv.totpSessionValid(req) {
		t.Fatal("no cookie should not validate")
	}

	req.AddCookie(&http.Cookie{Name: totpCookieName, Value: srv.totpCookieValue()})
	if !srv.totpSessionValid(req) {
		t.Fatal("valid cookie value should validate")
	}

	// A fresh request with a forged cookie value must not validate.
	forged := httptest.NewRequest(http.MethodGet, "/", nil)
	forged.AddCookie(&http.Cookie{Name: totpCookieName, Value: strings.Repeat("0", 64)})
	if srv.totpSessionValid(forged) {
		t.Fatal("forged cookie value must not validate")
	}

	// Deterministic across instances: same secret ⇒ same cookie value.
	srv2 := newTOTPTestServer(t, rfc6238Secret)
	if srv.totpCookieValue() != srv2.totpCookieValue() {
		t.Fatal("cookie value must be deterministic for a fixed secret")
	}
}

func TestSafeNext(t *testing.T) {
	keep := []string{"/", "/s/abc", "/s/abc?x=1", "/config", "/#/s/abc"}
	for _, s := range keep {
		if got := safeNext(s); got != s {
			t.Errorf("safeNext(%q) = %q, want %q", s, got, s)
		}
	}
	reject := []string{"", "//evil.com", "https://evil.com", "javascript:alert(1)", "/foo\r\nLocation: /", "relative/path"}
	for _, s := range reject {
		if got := safeNext(s); got != "/" {
			t.Errorf("safeNext(%q) = %q, want /", s, got)
		}
	}
}

// --- Middleware, end to end ---

func TestTOTPGate_BlocksWithoutCookie(t *testing.T) {
	resetTOTPRateLimits()
	srv := newTOTPTestServer(t, rfc6238Secret)
	h := srv.HTTPHandler()

	// Browser GET gets the login page at the requested URL.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/#/s/abc", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Access required") {
		t.Fatalf("GET without cookie: code=%d body=%s", w.Code, w.Body.String())
	}

	// API calls get a JSON 401.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/create/secret", strings.NewReader("{}")))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("POST without cookie: code=%d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "TOTP authentication required") {
		t.Fatalf("POST without cookie body: %s", w.Body.String())
	}

	// Health endpoints stay reachable for probes — real responses, not the login page.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"healthy"`) {
		t.Errorf("GET /health without cookie: code=%d body=%s, want health JSON", w.Code, w.Body.String())
	}

	// Everything else, including /version, is gated.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/version", nil))
	if !strings.Contains(w.Body.String(), "Access required") {
		t.Errorf("GET /version without cookie should serve the login page, got: %s", w.Body.String())
	}

	// CORS preflight passes through so corsMiddleware can answer it.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/create/secret", nil))
	if w.Code != http.StatusOK {
		t.Errorf("OPTIONS without cookie: code=%d, want 200", w.Code)
	}
}

func TestTOTPGate_ChinesePage(t *testing.T) {
	srv := newTOTPTestServer(t, rfc6238Secret)
	h := srv.HTTPHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	h.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "访问验证") {
		t.Fatalf("zh browser should get Chinese page, got: %s", w.Body.String())
	}
}

func TestTOTPGate_PassesWithCookie(t *testing.T) {
	resetTOTPRateLimits()
	srv := newTOTPTestServer(t, rfc6238Secret)
	h := srv.HTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.AddCookie(&http.Cookie{Name: totpCookieName, Value: srv.totpCookieValue()})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /config with cookie: code=%d, want 200", w.Code)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil {
		t.Fatalf("expected config JSON, got: %s", w.Body.String())
	}
}

func TestTOTPGate_LoginFlow(t *testing.T) {
	resetTOTPRateLimits()
	srv := newTOTPTestServer(t, rfc6238Secret)
	h := srv.HTTPHandler()

	// Wrong code redirects to the error page and does not set the cookie.
	form := "code=000000&next=%2Fs%2Fabc"
	w := httptest.NewRecorder()
	post := httptest.NewRequest(http.MethodPost, "/auth/totp", strings.NewReader(form))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(w, post)
	if w.Code != http.StatusFound {
		t.Fatalf("wrong code: code=%d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=1") || !strings.Contains(loc, "%2Fs%2Fabc") {
		t.Fatalf("wrong code Location = %q", loc)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("wrong code must not set the session cookie")
	}

	// Correct code logs in and redirects to the deep link.
	code := totpCode(rfc6238Secret, time.Now().Unix()/totpStepSeconds)
	post = httptest.NewRequest(http.MethodPost, "/auth/totp", strings.NewReader("code="+code+"&next=%2Fs%2Fabc"))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, post)
	if w.Code != http.StatusFound {
		t.Fatalf("correct code: code=%d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/s/abc" {
		t.Fatalf("correct code Location = %q, want /s/abc", loc)
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == totpCookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatal("correct code must set the session cookie")
	}

	// The issued cookie unlocks a previously gated endpoint.
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.AddCookie(session)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /config with logged-in cookie: code=%d", w.Code)
	}

	// Open redirect is refused: next=//evil.com lands on "/".
	post = httptest.NewRequest(http.MethodPost, "/auth/totp", strings.NewReader("code="+code+"&next=%2F%2Fevil.com"))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, post)
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("open redirect Location = %q, want /", loc)
	}
}

func TestTOTPGate_RateLimit(t *testing.T) {
	resetTOTPRateLimits()
	srv := newTOTPTestServer(t, rfc6238Secret)
	h := srv.HTTPHandler()

	// Exhaust the budget with wrong codes, then the next attempt is 429.
	for i := 0; i < totpRateLimitMax; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/totp", strings.NewReader("code=000000")))
		if w.Code != http.StatusFound {
			t.Fatalf("attempt %d: code=%d, want 302", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/totp", strings.NewReader("code=000000")))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited attempt: code=%d, want 429", w.Code)
	}
}

// TestTOTPGate_NoSecretMeansNoGate pins that the gate is inert unless a
// secret is configured: /create/secret is the API, not a login page.
func TestTOTPGate_NoSecretMeansNoGate(t *testing.T) {
	srv := newTOTPTestServer(t, nil)
	h := srv.HTTPHandler()

	body := `{"message":"` + pgpTestMessage + `","expiration":3600,"one_time":false,"require_auth":false}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/create/secret", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /create/secret without TOTPSecret: code=%d, want 200 (gate off)", w.Code)
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI(rfc6238Secret)
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
		t.Fatalf("unexpected provisioning URI: %s", uri)
	}
}
