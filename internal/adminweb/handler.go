package adminweb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/ratelimit"
)

const (
	sessionCookieName = "sevenmirror_admin_session"
	loginCodeLifetime = 10 * time.Minute
	sessionLifetime   = time.Hour
	maxLoginBody      = 4096
)

//go:embed templates/*.html assets/*.css
var files embed.FS

type Store interface {
	ListWorkspaces(context.Context) ([]admission.WorkspaceSummary, error)
	ListDevices(context.Context, admission.WorkspaceID) ([]admission.DeviceSummary, error)
}

type HandlerConfig struct {
	LoginCode      []byte
	ExpectedOrigin string
	Now            func() time.Time
	Random         io.Reader
}

type Handler struct {
	store          Store
	expectedOrigin string
	expectedHost   string
	secureCookies  bool
	now            func() time.Time
	random         io.Reader
	loginDigest    [sha256.Size]byte
	loginExpiresAt time.Time
	loginAttempts  *ratelimit.FixedWindow
	templates      *template.Template

	mu            sync.Mutex
	loginConsumed bool
	sessions      map[[sha256.Size]byte]session
}

type session struct {
	csrfToken string
	expiresAt time.Time
}

type dashboardView struct {
	CSRFToken  string
	Workspaces []workspaceView
}

type workspaceView struct {
	Name         string
	CreatedAt    string
	AndroidCount int
	ChromeCount  int
	PendingCount int
	RemovedCount int
	Devices      []deviceView
}

type deviceView struct {
	Name              string
	Type              string
	Status            string
	RegisteredAt      string
	ApprovedAt        string
	LastAuthenticated string
	LastActivity      string
	RemovedAt         string
}

func NewHandler(store Store, config HandlerConfig) (http.Handler, error) {
	if store == nil || len(config.LoginCode) == 0 {
		return nil, errors.New("admin store and login code are required")
	}
	origin, err := url.Parse(config.ExpectedOrigin)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.Host == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("admin expected origin must be an exact HTTP or HTTPS origin")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	attempts, err := ratelimit.NewFixedWindow(5, 128, time.Minute)
	if err != nil {
		return nil, err
	}
	templates, err := template.ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		store: store, expectedOrigin: origin.String(), expectedHost: origin.Host,
		secureCookies: origin.Scheme == "https", now: now, random: random,
		loginDigest:    sha256.Sum256(config.LoginCode),
		loginExpiresAt: now().Add(loginCodeLifetime), loginAttempts: attempts,
		templates: templates, sessions: make(map[[sha256.Size]byte]session),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handler.login)
	mux.HandleFunc("/logout", handler.logout)
	mux.HandleFunc("/assets/admin.css", handler.stylesheet)
	mux.HandleFunc("/", handler.dashboard)
	return handler.securityHeaders(mux), nil
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if _, ok := h.currentSession(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		h.render(w, "login.html", nil)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.validOrigin(r) {
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	client := remoteIP(r.RemoteAddr)
	if !h.loginAttempts.Allow(client, h.now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		h.renderLoginFailure(w)
		return
	}
	candidate := sha256.Sum256([]byte(r.PostForm.Get("login_code")))
	h.mu.Lock()
	valid := !h.loginConsumed && h.now().Before(h.loginExpiresAt) &&
		subtle.ConstantTimeCompare(candidate[:], h.loginDigest[:]) == 1
	if valid {
		h.loginConsumed = true
	}
	h.mu.Unlock()
	if !valid {
		h.renderLoginFailure(w)
		return
	}
	rawSession, err := randomToken(h.random)
	if err != nil {
		http.Error(w, "unable to start session", http.StatusInternalServerError)
		return
	}
	csrfToken, err := randomToken(h.random)
	if err != nil {
		http.Error(w, "unable to start session", http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256([]byte(rawSession))
	h.mu.Lock()
	h.sessions[digest] = session{csrfToken: csrfToken, expiresAt: h.now().Add(sessionLifetime)}
	h.mu.Unlock()
	h.setSessionCookie(w, rawSession, int(sessionLifetime.Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current, ok := h.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if !h.validOrigin(r) || subtle.ConstantTimeCompare(
		[]byte(r.FormValue("csrf_token")), []byte(current.csrfToken)) != 1 {
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	cookie, _ := r.Cookie(sessionCookieName)
	if cookie != nil {
		digest := sha256.Sum256([]byte(cookie.Value))
		h.mu.Lock()
		delete(h.sessions, digest)
		h.mu.Unlock()
	}
	h.setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current, ok := h.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	workspaces, err := h.store.ListWorkspaces(r.Context())
	if err != nil {
		http.Error(w, "unable to load the private space", http.StatusInternalServerError)
		return
	}
	view := dashboardView{CSRFToken: current.csrfToken}
	for index, workspace := range workspaces {
		devices, err := h.store.ListDevices(r.Context(), workspace.ID)
		if err != nil {
			http.Error(w, "unable to load devices", http.StatusInternalServerError)
			return
		}
		item := workspaceView{
			Name:      "私有空间 " + decimal(index+1),
			CreatedAt: formatTime(workspace.CreatedAt),
		}
		for _, device := range devices {
			if device.MembershipState == "approved" && !device.Revoked {
				if device.DeviceType == admission.DeviceAndroid {
					item.AndroidCount++
				} else if device.DeviceType == admission.DeviceChrome {
					item.ChromeCount++
				}
			}
			if (device.MembershipState == "pending_proof" ||
				device.MembershipState == "pending_approval") && !device.Revoked {
				item.PendingCount++
			}
			if device.Revoked {
				item.RemovedCount++
			}
			item.Devices = append(item.Devices, deviceView{
				Name: device.DeviceName, Type: deviceTypeLabel(device.DeviceType),
				Status: deviceStatus(device), RegisteredAt: formatTime(device.RegisteredAt),
				ApprovedAt:        formatOptionalTime(device.ApprovedAt),
				LastAuthenticated: formatOptionalTime(device.LastAuthenticatedAt),
				LastActivity:      activityLabel(device.LastActivityAt, h.now()),
				RemovedAt:         formatOptionalTime(device.RevokedAt),
			})
		}
		view.Workspaces = append(view.Workspaces, item)
	}
	h.render(w, "dashboard.html", view)
}

func (h *Handler) stylesheet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	encoded, err := files.ReadFile("assets/admin.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(encoded)
}

func (h *Handler) currentSession(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return session{}, false
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	h.mu.Lock()
	defer h.mu.Unlock()
	current, ok := h.sessions[digest]
	if !ok || !h.now().Before(current.expiresAt) {
		delete(h.sessions, digest)
		return session{}, false
	}
	return current, true
}

func (h *Handler) renderLoginFailure(w http.ResponseWriter) {
	h.renderStatus(w, http.StatusUnauthorized, "login.html", map[string]string{
		"Error": "登录码无效或已过期。请重新启动管理端获取新的登录码。",
	})
}

func (h *Handler) render(w http.ResponseWriter, name string, data any) {
	h.renderStatus(w, http.StatusOK, name, data)
}

func (h *Handler) renderStatus(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = h.templates.ExecuteTemplate(w, name, data)
}

func (h *Handler) validOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == h.expectedOrigin
}

func (h *Handler) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Host != h.expectedHost {
			http.Error(w, "request rejected", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: h.secureCookies, SameSite: http.SameSiteStrictMode,
	})
}

func randomToken(source io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func remoteIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return "unknown"
	}
	return host
}

func deviceTypeLabel(value admission.DeviceType) string {
	if value == admission.DeviceAndroid {
		return "Android"
	}
	if value == admission.DeviceChrome {
		return "Chrome"
	}
	return "未知设备"
}

func deviceStatus(device admission.DeviceSummary) string {
	if device.Revoked {
		return "已移除"
	}
	switch device.MembershipState {
	case "pending_proof":
		return "正在验证申请"
	case "pending_approval":
		return "等待批准"
	case "approved":
		return "已接入"
	default:
		return "状态需要检查"
	}
}

func activityLabel(value *time.Time, now time.Time) string {
	if value == nil {
		return "从未成功连接"
	}
	age := now.Sub(*value)
	if age < 0 {
		return formatTime(*value)
	}
	if age <= 2*time.Minute {
		return "刚刚活动"
	}
	if age <= time.Hour {
		return "最近活动"
	}
	return formatTime(*value)
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return "—"
	}
	return formatTime(*value)
}

func formatTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}

func decimal(value int) string {
	return strconv.Itoa(value)
}
