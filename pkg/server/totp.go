package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TOTP access gate.
//
// When Server.TOTPSecret is set, every request except /health, /ready and
// the gate's own endpoints requires a valid TOTP session cookie. The cookie
// is issued after the visitor proves possession of the shared TOTP secret by
// submitting a valid 6-digit code. This protects the whole instance (UI and
// API) behind a single authenticator app — a door lock, not per-user auth.
// It is independent of OIDC: both can be enabled at once.

const (
	// totpCookieName is the HttpOnly cookie carrying the gate session.
	totpCookieName = "yopass_totp"
	// totpSessionMaxAge bounds how long a verified session lasts before the
	// code has to be entered again.
	totpSessionMaxAge = 7 * 24 * time.Hour
	// totpStepSeconds is the RFC 6238 time-step.
	totpStepSeconds int64 = 30
	// totpSkewSteps is how many steps before/after now are accepted, covering
	// authenticator clock drift of up to ~1 minute.
	totpSkewSteps int = 1
	// totpRateLimitMax and totpRateLimitWindow throttle failed attempts per
	// IP: at 10 guesses/minute brute-forcing six digits would take months.
	totpRateLimitMax    = 10
	totpRateLimitWindow = time.Minute
)

// ParseTOTPSecret normalizes a base32 TOTP secret (accepts spaces/hyphens
// and optional padding, e.g. as copied from a provisioning tool) and returns
// the decoded bytes. Bad inputs (too short, invalid characters) fail loudly
// so a typo can't silently weaken the gate.
func ParseTOTPSecret(raw string) ([]byte, error) {
	normalized := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(raw))
	for _, enc := range []*base32.Encoding{base32.StdEncoding.WithPadding(base32.NoPadding), base32.StdEncoding} {
		if b, err := enc.DecodeString(normalized); err == nil {
			if len(b) < 16 {
				return nil, fmt.Errorf("TOTP secret must decode to at least 16 bytes")
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("TOTP secret is not valid base32 (A-Z2-7)")
}

// TOTPProvisioningURI renders the otpauth:// URI for scanning into an
// authenticator app, built from the already-configured secret.
func TOTPProvisioningURI(secret []byte) string {
	return "otpauth://totp/Yopass:admin?issuer=Yopass&secret=" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// totpCode computes the 6-digit RFC 6238 code for counter using HMAC-SHA1.
func totpCode(secret []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", v)
}

// verifyTOTP reports whether code is valid for secret at the current time,
// accepting ±totpSkewSteps. Comparison is constant-time per candidate; the
// format check (length, digits only) short-circuits on shape alone.
func verifyTOTP(secret []byte, code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	now := time.Now().Unix() / totpStepSeconds
	for step := -totpSkewSteps; step <= totpSkewSteps; step++ {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, now+int64(step))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// totpCookieValue returns the value a valid gate-session cookie must carry:
// an HMAC over a constant string keyed with the gate secret. It holds no
// data, so signing alone suffices — no encryption required. Deriving from
// the shared secret keeps sessions valid across instances and restarts,
// unlike random per-instance keys.
func (y *Server) totpCookieValue() string {
	mac := hmac.New(sha256.New, y.TOTPSecret)
	mac.Write([]byte("yopass-totp-session-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

func (y *Server) totpSessionValid(r *http.Request) bool {
	c, err := r.Cookie(totpCookieName)
	if err != nil {
		return false
	}
	want := y.totpCookieValue()
	return len(c.Value) == len(want) && subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

func (y *Server) setTOTPCookie(w http.ResponseWriter, r *http.Request) {
	sameSite := http.SameSiteLaxMode
	secure := y.isSecure(r)
	if y.isCrossOrigin(r) {
		sameSite = http.SameSiteNoneMode
		secure = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     totpCookieName,
		Value:    y.totpCookieValue(),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   int(totpSessionMaxAge.Seconds()),
	})
}

// safeNext validates the post-login redirect target so a crafted "next"
// value cannot turn the login into an open redirect (or smuggle a
// header-injecting Location header).
func safeNext(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\r\n") {
		return "/"
	}
	return s
}

// totpLoginHandler verifies the submitted code and issues the session cookie.
// The request-URI is preserved as "next" so deep links (e.g. a secret URL)
// work after the login.
func (y *Server) totpLoginHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid form")
		return
	}
	ip := y.getRealClientIP(r)

	if !totpRateLimitAllow(ip) {
		y.newAuditor("auth.totp_failed", ip, nil).denied("too many attempts")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	next := safeNext(r.FormValue("next"))
	if !verifyTOTP(y.TOTPSecret, r.FormValue("code")) {
		y.newAuditor("auth.totp_failed", ip, nil).denied("invalid code")
		totpRateLimitRecord(ip)
		http.Redirect(w, r, "/auth/totp?error=1&next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	totpRateLimitReset(ip)
	y.setTOTPCookie(w, r)
	y.newAuditor("auth.totp_passed", ip, nil).success()
	http.Redirect(w, r, next, http.StatusFound)
}

// totpRememberJS is injected into the login page. Yopass deep links carry
// their payload in the URL fragment (e.g. /#/s/{uuid}/{key}), which browsers
// never send to the server — so the gate's login redirect can only return the
// visitor to the server-visible path. This script snapshots the real URL into
// sessionStorage before the form navigation discards it; the web app restores
// it on boot (see main.tsx). Same-origin and load-time only, so the strict
// script-src 'self' CSP stays intact.
const totpRememberJS = `(function () {
  if (location.pathname.indexOf('/auth/totp') === 0) return;
  if (location.pathname === '/' && !location.hash && !location.search) return;
  if (!sessionStorage.getItem('yopass_totp_next')) {
    sessionStorage.setItem('yopass_totp_next', location.href);
  }
})();`

// totpRememberJSHandler serves the remember-script for the login page.
func (y *Server) totpRememberJSHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(totpRememberJS))
}

// serveTOTPPage renders the gate's login page. It is served both at
// /auth/totp (after a failed attempt, carrying error=1 and next=) and, for
// unmatched browser GETs, at the original URL so the address bar keeps the
// deep link.
func (y *Server) serveTOTPPage(w http.ResponseWriter, r *http.Request, next string, showError bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := totpPageTmpl[0]
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "zh") {
		page = totpPageTmpl[1]
	}
	if err := page.Execute(w, struct {
		Next  string
		Error bool
	}{next, showError}); err != nil {
		y.Logger.Error("failed to render TOTP login page", zap.Error(err))
	}
}

// totpPageHandler serves the page for GET /auth/totp (used as the error
// landing page; also reachable directly).
func (y *Server) totpPageHandler(w http.ResponseWriter, r *http.Request) {
	y.serveTOTPPage(w, r, safeNext(r.URL.Query().Get("next")), r.URL.Query().Get("error") == "1")
}

// --- Per-IP failure rate limit --------------------------------------------
// In-memory sliding window. A single instance sees all attempts; operators
// running several instances behind a load balancer should rate-limit at the
// proxy as well, since each instance keeps its own window.

type totpRateLimiter struct {
	mu sync.Mutex
	// ip -> timestamps of recent failed attempts
	failures map[string][]time.Time
}

var totpRates = &totpRateLimiter{failures: make(map[string][]time.Time)}

// totpRateLimitAllow reports whether ip may attempt a code right now. Old
// entries are pruned on every call so the map cannot grow without bound.
func totpRateLimitAllow(ip string) bool {
	totpRates.mu.Lock()
	defer totpRates.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-totpRateLimitWindow)
	kept := totpRates.failures[ip][:0]
	for _, t := range totpRates.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	totpRates.failures[ip] = kept
	return len(kept) < totpRateLimitMax
}

// totpRateLimitRecord remembers a failed attempt from ip.
func totpRateLimitRecord(ip string) {
	totpRates.mu.Lock()
	defer totpRates.mu.Unlock()
	totpRates.failures[ip] = append(totpRates.failures[ip], time.Now())
}

// totpRateLimitReset drops the failed-attempt history for ip after a success.
func totpRateLimitReset(ip string) {
	totpRates.mu.Lock()
	defer totpRates.mu.Unlock()
	delete(totpRates.failures, ip)
}

// requireTOTPMiddleware gates every route behind the gate. Browser
// navigations (GET/HEAD) receive the login page at the requested URL, other
// methods get a JSON 401 so API clients get a machine-readable answer.
// OPTIONS passes through so CORS preflights are answered by corsMiddleware.
func (y *Server) requireTOTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if y.totpSessionValid(r) {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case r.Method == http.MethodOptions,
			r.URL.Path == "/health" || r.URL.Path == "/ready",
			strings.HasPrefix(r.URL.Path, "/auth/totp"):
			next.ServeHTTP(w, r)
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			y.serveTOTPPage(w, r, safeNext(r.URL.RequestURI()), false)
		default:
			y.newAuditor("auth.totp_blocked", y.getRealClientIP(r), nil).denied("no session")
			jsonError(w, http.StatusUnauthorized, "TOTP authentication required")
		}
	})
}

// totpPageTmpl renders the gate page. Inline scripts are impossible here:
// the response passes through SecurityHeadersHandler whose CSP forbids them,
// which conveniently also neuters any script injection. [next] and [error]
// are escaped by html/template.
var totpPageTmpl = []*template.Template{
	template.Must(template.New("en").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access required — Yopass</title>
<script src="/auth/totp/remember.js"></script>
<style>
  body { font-family: system-ui, sans-serif; background: #f6f6f6; display: flex; min-height: 100vh; margin: 0; }
  main { margin: auto; background: #fff; border-radius: 12px; padding: 2.5rem; width: min(22rem, 90vw); box-shadow: 0 10px 30px rgba(0,0,0,.1); }
  h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
  p { color: #555; margin: 0 0 1.5rem; font-size: .95rem; }
  label { display: block; font-size: .8rem; color: #333; margin-bottom: .4rem; }
  input { width: 100%; box-sizing: border-box; padding: .7rem; font-size: 1.4rem; letter-spacing: .4em; text-align: center; border: 1px solid #ccc; border-radius: 8px; }
  input:focus { outline: 2px solid #34d399; border-color: #34d399; }
  button { width: 100%; margin-top: 1rem; padding: .7rem; font-size: 1rem; font-weight: 600; color: #fff; background: #059669; border: 0; border-radius: 8px; cursor: pointer; }
  button:hover { background: #047857; }
  .error { background: #fee2e2; color: #991b1b; border-radius: 8px; padding: .7rem; margin-bottom: 1rem; font-size: .9rem; }
</style></head><body><main>
  <h1>Access required</h1>
  <p>This Yopass instance is protected. Enter the 6-digit code from your authenticator app to continue.</p>
  {{if .Error}}<div class="error" role="alert">Invalid code, please try again.</div>{{end}}
  <form method="post" action="/auth/totp">
    <input type="hidden" name="next" value="{{.Next}}">
    <label for="code">Authenticator code</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus>
    <button type="submit">Verify</button>
  </form>
</main></body></html>`)),
	template.Must(template.New("zh").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>访问验证 — Yopass</title>
<script src="/auth/totp/remember.js"></script>
<style>
  body { font-family: system-ui, sans-serif; background: #f6f6f6; display: flex; min-height: 100vh; margin: 0; }
  main { margin: auto; background: #fff; border-radius: 12px; padding: 2.5rem; width: min(22rem, 90vw); box-shadow: 0 10px 30px rgba(0,0,0,.1); }
  h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
  p { color: #555; margin: 0 0 1.5rem; font-size: .95rem; }
  label { display: block; font-size: .8rem; color: #333; margin-bottom: .4rem; }
  input { width: 100%; box-sizing: border-box; padding: .7rem; font-size: 1.4rem; letter-spacing: .4em; text-align: center; border: 1px solid #ccc; border-radius: 8px; }
  input:focus { outline: 2px solid #34d399; border-color: #34d399; }
  button { width: 100%; margin-top: 1rem; padding: .7rem; font-size: 1rem; font-weight: 600; color: #fff; background: #059669; border: 0; border-radius: 8px; cursor: pointer; }
  button:hover { background: #047857; }
  .error { background: #fee2e2; color: #991b1b; border-radius: 8px; padding: .7rem; margin-bottom: 1rem; font-size: .9rem; }
</style></head><body><main>
  <h1>访问验证</h1>
  <p>此 Yopass 实例受保护。请输入身份验证器应用中的 6 位验证码以继续访问。</p>
  {{if .Error}}<div class="error" role="alert">验证码无效，请重试。</div>{{end}}
  <form method="post" action="/auth/totp">
    <input type="hidden" name="next" value="{{.Next}}">
    <label for="code">身份验证器验证码</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus>
    <button type="submit">验证</button>
  </form>
</main></body></html>`)),
}
