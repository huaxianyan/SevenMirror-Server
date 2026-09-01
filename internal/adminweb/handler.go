package adminweb

import (
	"context"
	"crypto/hmac"
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

	"github.com/huaxianyan/SyncNotifications-Server/internal/adminservice"
	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/ratelimit"
)

const (
	sessionCookieName = "sevenmirror_admin_session"
	loginCodeLifetime = 10 * time.Minute
	sessionLifetime   = time.Hour
	maxFormBody       = 4096
)

//go:embed templates/*.html assets/*.css
var files embed.FS

type Manager interface {
	ListWorkspaces(context.Context) ([]admission.WorkspaceSummary, error)
	ListDevices(context.Context, admission.WorkspaceID) ([]admission.DeviceSummary, error)
	IssuePairingCode(context.Context, admission.WorkspaceID, admission.DeviceType, string, time.Time, time.Duration) (adminservice.PairingCode, error)
	ApproveDevice(context.Context, admission.WorkspaceID, string, time.Time) (admission.ApprovedMembership, error)
	RenameDevice(context.Context, admission.WorkspaceID, string, string, time.Time) (admission.RenamedDevice, error)
	ChangeDeviceAccess(context.Context, admission.WorkspaceID, string, adminservice.DeviceAccessAction, time.Time) (admission.RevokedDevice, error)
}

type HandlerConfig struct {
	LoginCode      []byte
	ExpectedOrigin string
	Now            func() time.Time
	Random         io.Reader
}

type Handler struct {
	manager           Manager
	expectedOrigin    string
	expectedHost      string
	secureCookies     bool
	now               func() time.Time
	random            io.Reader
	workspaceRefKey   [sha256.Size]byte
	loginDigest       [sha256.Size]byte
	loginExpiresAt    time.Time
	loginAttempts     *ratelimit.FixedWindow
	managementActions *ratelimit.FixedWindow
	templates         *template.Template

	mu            sync.Mutex
	loginConsumed bool
	sessions      map[[sha256.Size]byte]session
}

type session struct {
	csrfToken string
	expiresAt time.Time
	flash     *flashMessage
}

type flashMessage struct {
	Kind    string
	Message string
	Secret  string
}

type dashboardView struct {
	CSRFToken  string
	Flash      *flashMessage
	Workspaces []workspaceView
}

type workspaceView struct {
	Reference    string
	Name         string
	CreatedAt    string
	AndroidCount int
	ChromeCount  int
	PendingCount int
	RemovedCount int
	Devices      []deviceView
}

type deviceView struct {
	Reference         string
	Name              string
	Type              string
	Status            string
	RegisteredAt      string
	ApprovedAt        string
	LastAuthenticated string
	LastActivity      string
	RemovedAt         string
	CanApprove        bool
	CanReject         bool
	CanRename         bool
	CanRemove         bool
}

func NewHandler(manager Manager, config HandlerConfig) (http.Handler, error) {
	if manager == nil || len(config.LoginCode) == 0 {
		return nil, errors.New("admin manager and login code are required")
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
	loginAttempts, err := ratelimit.NewFixedWindow(5, 128, time.Minute)
	if err != nil {
		return nil, err
	}
	managementActions, err := ratelimit.NewFixedWindow(30, 128, time.Minute)
	if err != nil {
		return nil, err
	}
	templates, err := template.ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		manager: manager, expectedOrigin: origin.String(), expectedHost: origin.Host,
		secureCookies: origin.Scheme == "https", now: now, random: random,
		loginDigest: sha256.Sum256(config.LoginCode), loginExpiresAt: now().Add(loginCodeLifetime),
		loginAttempts: loginAttempts, managementActions: managementActions,
		templates: templates, sessions: make(map[[sha256.Size]byte]session),
	}
	if _, err := io.ReadFull(random, handler.workspaceRefKey[:]); err != nil {
		return nil, errors.New("generate workspace reference key")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handler.login)
	mux.HandleFunc("/logout", handler.logout)
	mux.HandleFunc("/actions/pairing-code", handler.issuePairingCode)
	mux.HandleFunc("/actions/approve", handler.approveDevice)
	mux.HandleFunc("/actions/reject", handler.rejectDevice)
	mux.HandleFunc("/actions/rename", handler.renameDevice)
	mux.HandleFunc("/actions/remove", handler.removeDevice)
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
		if _, _, ok := h.currentSession(r); ok {
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
	if !h.loginAttempts.Allow(remoteIP(r.RemoteAddr), h.now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
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
	_, digest, ok := h.authorizeManagementPost(w, r)
	if !ok {
		return
	}
	h.mu.Lock()
	delete(h.sessions, digest)
	h.mu.Unlock()
	h.setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) issuePairingCode(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.authorizeManagementPost(w, r)
	if !ok {
		return
	}
	workspaceID, ok := h.resolveWorkspace(r.Context(), r.PostForm.Get("workspace_ref"))
	if !ok {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	issued, err := h.manager.IssuePairingCode(
		r.Context(), workspaceID, admission.DeviceType(r.PostForm.Get("device_type")),
		r.PostForm.Get("device_name"), h.now(), adminservice.DefaultPairingCodeLifetime)
	if err != nil {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	h.finishAction(w, r, digest, &flashMessage{
		Kind: "success", Message: "加入码已生成，有效期至 " + formatTime(issued.ExpiresAt) + "。",
		Secret: issued.Code,
	})
}

func (h *Handler) approveDevice(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.authorizeManagementPost(w, r)
	if !ok {
		return
	}
	workspaceID, ok := h.resolveWorkspace(r.Context(), r.PostForm.Get("workspace_ref"))
	if !ok {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	deviceReference, ok := h.resolveDeviceReference(
		r.Context(), workspaceID, r.PostForm.Get("device_ref"))
	if !ok {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	if _, err := h.manager.ApproveDevice(
		r.Context(), workspaceID, deviceReference, h.now()); err != nil {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	h.finishAction(w, r, digest, &flashMessage{
		Kind: "success", Message: "设备已批准，可以继续完成连接。",
	})
}

func (h *Handler) rejectDevice(w http.ResponseWriter, r *http.Request) {
	h.changeDeviceAccess(w, r, adminservice.RejectPending,
		"申请已拒绝，这台设备不能接入私有空间。")
}

func (h *Handler) renameDevice(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.authorizeManagementPost(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	workspaceID, ok := h.resolveWorkspace(r.Context(), r.PostForm.Get("workspace_ref"))
	if !ok {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	deviceReference, ok := h.resolveDeviceReference(
		r.Context(), workspaceID, r.PostForm.Get("device_ref"))
	if !ok {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	if _, err := h.manager.RenameDevice(r.Context(), workspaceID, deviceReference,
		r.PostForm.Get("new_name"), h.now()); err != nil {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	h.finishAction(w, r, digest, &flashMessage{
		Kind: "success", Message: "设备名称已更新。已接入设备将在同步后显示新名称。",
	})
}

func (h *Handler) removeDevice(w http.ResponseWriter, r *http.Request) {
	h.changeDeviceAccess(w, r, adminservice.RemoveApproved,
		"设备已移除，需要重新申请才能再次接入。")
}

func (h *Handler) changeDeviceAccess(
	w http.ResponseWriter,
	r *http.Request,
	action adminservice.DeviceAccessAction,
	successMessage string,
) {
	_, digest, ok := h.authorizeManagementPost(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	workspaceID, ok := h.resolveWorkspace(r.Context(), r.PostForm.Get("workspace_ref"))
	if !ok {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	deviceReference, ok := h.resolveDeviceReference(
		r.Context(), workspaceID, r.PostForm.Get("device_ref"))
	if !ok {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	if _, err := h.manager.ChangeDeviceAccess(
		r.Context(), workspaceID, deviceReference, action, h.now()); err != nil {
		h.finishAction(w, r, digest, actionFailure())
		return
	}
	h.finishAction(w, r, digest, &flashMessage{Kind: "success", Message: successMessage})
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
	current, digest, ok := h.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	view := dashboardView{CSRFToken: current.csrfToken, Flash: h.takeFlash(digest)}
	workspaces, err := h.manager.ListWorkspaces(r.Context())
	if err != nil {
		http.Error(w, "unable to load the private space", http.StatusInternalServerError)
		return
	}
	for index, workspace := range workspaces {
		devices, err := h.manager.ListDevices(r.Context(), workspace.ID)
		if err != nil {
			http.Error(w, "unable to load devices", http.StatusInternalServerError)
			return
		}
		item := workspaceView{
			Reference: h.workspaceReference(workspace.ID),
			Name:      "私有空间 " + strconv.Itoa(index+1), CreatedAt: formatTime(workspace.CreatedAt),
		}
		for _, device := range devices {
			if device.MembershipState == "approved" && !device.Revoked {
				if device.DeviceType == admission.DeviceAndroid {
					item.AndroidCount++
				} else if device.DeviceType == admission.DeviceChrome {
					item.ChromeCount++
				}
			}
			pending := (device.MembershipState == "pending_proof" ||
				device.MembershipState == "pending_approval") && !device.Revoked
			if pending {
				item.PendingCount++
			}
			if device.Revoked {
				item.RemovedCount++
			}
			item.Devices = append(item.Devices, deviceView{
				Reference: h.deviceActionReference(workspace.ID, device.Reference),
				Name:      device.DeviceName,
				Type:      deviceTypeLabel(device.DeviceType), Status: deviceStatus(device),
				RegisteredAt:      formatTime(device.RegisteredAt),
				ApprovedAt:        formatOptionalTime(device.ApprovedAt),
				LastAuthenticated: formatOptionalTime(device.LastAuthenticatedAt),
				LastActivity:      activityLabel(device.LastActivityAt, h.now()),
				RemovedAt:         formatOptionalTime(device.RevokedAt),
				CanApprove:        device.MembershipState == "pending_approval" && !device.Revoked,
				CanReject:         pending,
				CanRename:         device.MembershipState == "approved" && !device.Revoked,
				CanRemove:         device.MembershipState == "approved" && !device.Revoked,
			})
		}
		view.Workspaces = append(view.Workspaces, item)
	}
	h.render(w, "dashboard.html", view)
}

func (h *Handler) authorizeManagementPost(
	w http.ResponseWriter,
	r *http.Request,
) (session, [sha256.Size]byte, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return session{}, [sha256.Size]byte{}, false
	}
	current, digest, ok := h.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return session{}, [sha256.Size]byte{}, false
	}
	if !h.managementActions.Allow(base64.RawURLEncoding.EncodeToString(digest[:]), h.now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many actions", http.StatusTooManyRequests)
		return session{}, [sha256.Size]byte{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil || !h.validOrigin(r) ||
		subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf_token")),
			[]byte(current.csrfToken)) != 1 {
		http.Error(w, "request rejected", http.StatusForbidden)
		return session{}, [sha256.Size]byte{}, false
	}
	return current, digest, true
}

func (h *Handler) resolveWorkspace(
	ctx context.Context,
	reference string,
) (admission.WorkspaceID, bool) {
	workspaces, err := h.manager.ListWorkspaces(ctx)
	if err != nil {
		return admission.WorkspaceID{}, false
	}
	var matched *admission.WorkspaceID
	for _, workspace := range workspaces {
		candidate := h.workspaceReference(workspace.ID)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(reference)) == 1 {
			copyOfID := workspace.ID
			matched = &copyOfID
		}
	}
	if matched == nil {
		return admission.WorkspaceID{}, false
	}
	return *matched, true
}

func (h *Handler) workspaceReference(workspaceID admission.WorkspaceID) string {
	return h.actionReference("workspace", workspaceID[:])
}

func (h *Handler) deviceActionReference(
	workspaceID admission.WorkspaceID,
	deviceReference string,
) string {
	value := append(append([]byte(nil), workspaceID[:]...), []byte(deviceReference)...)
	return h.actionReference("device", value)
}

func (h *Handler) actionReference(domain string, value []byte) string {
	mac := hmac.New(sha256.New, h.workspaceRefKey[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(value)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
}

func (h *Handler) resolveDeviceReference(
	ctx context.Context,
	workspaceID admission.WorkspaceID,
	actionReference string,
) (string, bool) {
	devices, err := h.manager.ListDevices(ctx, workspaceID)
	if err != nil {
		return "", false
	}
	var matched string
	for _, device := range devices {
		candidate := h.deviceActionReference(workspaceID, device.Reference)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(actionReference)) == 1 {
			if matched != "" {
				return "", false
			}
			matched = device.Reference
		}
	}
	return matched, matched != ""
}

func (h *Handler) finishAction(
	w http.ResponseWriter,
	r *http.Request,
	digest [sha256.Size]byte,
	message *flashMessage,
) {
	h.mu.Lock()
	current, ok := h.sessions[digest]
	if ok {
		current.flash = message
		h.sessions[digest] = current
	}
	h.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) takeFlash(digest [sha256.Size]byte) *flashMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	current, ok := h.sessions[digest]
	if !ok || current.flash == nil {
		return nil
	}
	message := current.flash
	current.flash = nil
	h.sessions[digest] = current
	return message
}

func actionFailure() *flashMessage {
	return &flashMessage{
		Kind: "error", Message: "操作没有完成。请刷新设备状态后重试。",
	}
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

func (h *Handler) currentSession(r *http.Request) (session, [sha256.Size]byte, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return session{}, [sha256.Size]byte{}, false
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	h.mu.Lock()
	defer h.mu.Unlock()
	current, ok := h.sessions[digest]
	if !ok || !h.now().Before(current.expiresAt) {
		delete(h.sessions, digest)
		return session{}, [sha256.Size]byte{}, false
	}
	return current, digest, true
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
		if device.ApprovedAt == nil {
			return "申请已拒绝"
		}
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
