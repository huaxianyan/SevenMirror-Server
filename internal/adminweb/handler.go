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
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/adminservice"
	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
	"github.com/huaxianyan/SyncNotifications-Server/internal/ratelimit"
)

const (
	sessionCookieName     = "sevenmirror_admin_session"
	recoveryCodeLifetime  = 10 * time.Minute
	sessionLifetime       = 8 * time.Hour
	maxFormBody           = 4096
	recoveryCodeFormField = "recovery_code"

	setupPath       = "/setup"
	setupFactorPath = "/setup/totp"
)

// setupPendingLifetime bounds how long a half-finished credential change stays
// usable. The pending state lives in the session, so a restart of the console
// simply asks the administrator to start the setup over.
const setupPendingLifetime = 10 * time.Minute

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
	RecoveryCode      []byte
	ExpectedOrigin    string
	TrustedProxyCIDRs []netip.Prefix
	Now               func() time.Time
	Random            io.Reader
}

type Handler struct {
	manager           Manager
	accounts          AccountStore
	expectedOrigin    string
	expectedHost      string
	secureCookies     bool
	now               func() time.Time
	random            io.Reader
	workspaceRefKey   [sha256.Size]byte
	recoveryDigest    [sha256.Size]byte
	recoveryExpiresAt time.Time
	clientAddresses   clientaddress.Resolver
	loginAttempts     *ratelimit.FixedWindow
	setupAttempts     *ratelimit.FixedWindow
	managementActions *ratelimit.FixedWindow
	templates         *template.Template

	mu           sync.Mutex
	account      account
	recoveryUsed bool
	sessions     map[[sha256.Size]byte]session
}

type session struct {
	csrfToken      string
	expiresAt      time.Time
	flash          *flashMessage
	mustInitialize bool
	pending        *pendingSetup
}

// pendingSetup is a credential change whose password and TOTP secret are already
// decided but not yet stored: it waits for one correct code from the new
// authenticator entry. The password travels hashed, so the plaintext is never held
// beyond the request that submitted it.
type pendingSetup struct {
	name         string
	passwordHash string
	secret       []byte
	secondFactor *totpVerifier
	expiresAt    time.Time
}

type flashMessage struct {
	Kind    string
	Message string
	Secret  string
}

type loginView struct {
	FirstRun bool
	Error    string
}

type setupFormView struct {
	CSRFToken   string
	Name        string
	MinPassword int
	FirstRun    bool
	Error       string
}

// setupFactorView carries the freshly generated shared secret. It is rendered
// exactly once, in the response to the step that created it: the secret is not
// readable again after this page, so a lost authenticator entry is replaced by
// running the setup again rather than by looking the secret up.
type setupFactorView struct {
	CSRFToken string
	Name      string
	Secret    string
	URI       string
	FirstRun  bool
	Error     string
}

type dashboardView struct {
	CSRFToken      string
	Flash          *flashMessage
	AccountName    string
	AccountUpdated string
	Workspaces     []workspaceView
}

type workspaceView struct {
	Reference      string
	Name           string
	CreatedAt      string
	AndroidCount   int
	ChromeCount    int
	PendingCount   int
	RemovedCount   int
	PendingDevices []deviceView
	ActiveDevices  []deviceView
	PastDevices    []deviceView
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

func NewHandler(manager Manager, accounts AccountStore, config HandlerConfig) (http.Handler, error) {
	if manager == nil || accounts == nil {
		return nil, errors.New("admin manager and account store are required")
	}
	credential, found, err := accounts.LoadAdministrator(context.Background())
	if err != nil {
		return nil, err
	}
	current := defaultAccount()
	if found {
		current, err = accountFromCredential(credential)
		if err != nil {
			return nil, err
		}
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
	// The credential setup has its own, looser window. It is already behind a signed
	// in session, and negotiating a password policy is the one flow where a person
	// legitimately submits several times in a row: sharing the five-per-minute login
	// bucket with it would lock the administrator out of their own first sign-in.
	setupAttempts, err := ratelimit.NewFixedWindow(20, 128, time.Minute)
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
		manager: manager, accounts: accounts,
		expectedOrigin: origin.String(), expectedHost: origin.Host,
		secureCookies: origin.Scheme == "https", now: now, random: random,
		account:           current,
		recoveryDigest:    sha256.Sum256(config.RecoveryCode),
		recoveryExpiresAt: now().Add(recoveryCodeLifetime),
		recoveryUsed:      len(config.RecoveryCode) == 0,
		clientAddresses:   clientaddress.New(config.TrustedProxyCIDRs),
		loginAttempts:     loginAttempts,
		setupAttempts:     setupAttempts,
		managementActions: managementActions,
		templates:         templates,
		sessions:          make(map[[sha256.Size]byte]session),
	}
	if _, err := io.ReadFull(random, handler.workspaceRefKey[:]); err != nil {
		return nil, errors.New("generate workspace reference key")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handler.login)
	mux.HandleFunc("/logout", handler.logout)
	mux.HandleFunc(setupFactorPath, handler.setupSecondFactor)
	mux.HandleFunc(setupPath, handler.setupCredential)
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
		if current, _, ok := h.currentSession(r); ok {
			http.Redirect(w, r, landingPath(current), http.StatusSeeOther)
			return
		}
		h.render(w, "login.html", h.loginView(""))
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
	if !h.allowAttempts(h.loginAttempts, w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		h.renderLoginFailure(w)
		return
	}
	if !h.authenticate(r) {
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
	mustInitialize := !h.account.initialized
	h.sessions[digest] = session{
		csrfToken: csrfToken, expiresAt: h.now().Add(sessionLifetime),
		mustInitialize: mustInitialize,
	}
	h.mu.Unlock()
	h.setSessionCookie(w, rawSession, int(sessionLifetime.Seconds()))
	http.Redirect(w, r, landingPath(session{mustInitialize: mustInitialize}), http.StatusSeeOther)
}

func landingPath(current session) string {
	if current.mustInitialize {
		return setupPath
	}
	return "/"
}

// authenticate evaluates the account name and the password verifier before the
// second factor, and answers with a single boolean so a failure never reports
// which of them was wrong. The password verifier runs even when the name did not
// match, so the response time does not reveal whether the account is correct.
//
// The second factor is consulted only after the name and password matched: a
// mistyped password must not consume the current time step, which would otherwise
// reject the correct retry inside the same thirty second window.
func (h *Handler) authenticate(r *http.Request) bool {
	if candidate := strings.TrimSpace(r.PostForm.Get(recoveryCodeFormField)); candidate != "" {
		return h.consumeRecoveryCode(candidate)
	}
	current := h.currentAccount()
	nameMatched := current.nameMatches(strings.TrimSpace(r.PostForm.Get("username")))
	passwordMatched := current.passwordMatches(r.PostForm.Get("password"))
	if !nameMatched || !passwordMatched {
		return false
	}
	if !current.initialized {
		return true
	}
	return current.secondFactor.verify(r.PostForm.Get("totp_code"), h.now())
}

func (h *Handler) currentAccount() account {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.account
}

func (h *Handler) loginView(message string) loginView {
	current := h.currentAccount()
	return loginView{FirstRun: !current.initialized, Error: message}
}

// consumeRecoveryCode accepts the one-time code printed when the process starts.
// It is the escape hatch for a lost authenticator device: single use, and expired
// ten minutes after startup.
func (h *Handler) consumeRecoveryCode(candidate string) bool {
	digest := sha256.Sum256([]byte(candidate))
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.recoveryUsed || !h.now().Before(h.recoveryExpiresAt) ||
		subtle.ConstantTimeCompare(digest[:], h.recoveryDigest[:]) != 1 {
		return false
	}
	h.recoveryUsed = true
	return true
}

// clientAddress resolves the address the login limiter is keyed on. Behind the
// reverse proxy every request arrives from the proxy itself, so the forwarded
// address is used only when the direct peer is a configured trusted proxy.
func (h *Handler) clientAddress(r *http.Request) string {
	address, err := h.clientAddresses.Resolve(r)
	if err != nil {
		return "invalid"
	}
	return address
}

// allowAttempts spends one attempt from the given window for the calling client,
// answering with 429 when the window is exhausted.
func (h *Handler) allowAttempts(limited *ratelimit.FixedWindow, w http.ResponseWriter, r *http.Request) bool {
	if limited.Allow(h.clientAddress(r), h.now()) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	http.Error(w, "too many attempts", http.StatusTooManyRequests)
	return false
}

// setupCredential renders and accepts the first half of a credential change: the
// account name, the new password and the binding of an authenticator. The shared
// secret is generated here so the second step can show it before anything is
// stored, which is what makes the confirmation meaningful.
func (h *Handler) setupCredential(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != setupPath {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		current, _, ok := h.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h.render(w, "setup.html", setupFormView{
			CSRFToken: current.csrfToken, Name: h.currentAccount().name,
			MinPassword: minPasswordBytes, FirstRun: current.mustInitialize,
		})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current, digest, ok := h.authorizeSessionPost(w, r)
	if !ok {
		return
	}
	if !h.allowAttempts(h.setupAttempts, w, r) {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	fail := func(message string) {
		h.renderStatus(w, http.StatusBadRequest, "setup.html", setupFormView{
			CSRFToken: current.csrfToken, Name: name,
			MinPassword: minPasswordBytes, FirstRun: current.mustInitialize, Error: message,
		})
	}
	if err := validateAccountName(name); err != nil {
		fail(err.Error())
		return
	}
	if r.PostForm.Get("password_confirm") != password {
		fail("两次输入的新密码不一致。")
		return
	}
	if err := validateNewPassword(password); err != nil {
		fail(err.Error())
		return
	}
	encoded, err := hashPassword(password)
	if err != nil {
		http.Error(w, "unable to prepare the credential", http.StatusInternalServerError)
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		http.Error(w, "unable to generate the authenticator secret", http.StatusInternalServerError)
		return
	}
	pending := &pendingSetup{
		name: name, passwordHash: encoded, secret: secret,
		secondFactor: newTOTPVerifier(secret),
		expiresAt:    h.now().Add(setupPendingLifetime),
	}
	h.mu.Lock()
	stored, found := h.sessions[digest]
	if found {
		stored.pending = pending
		h.sessions[digest] = stored
	}
	h.mu.Unlock()
	if !found {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	h.renderFactor(w, http.StatusOK, current, pending, "")
}

// setupSecondFactor accepts the one code that proves the authenticator entry was
// created correctly, and only then writes the credential.
func (h *Handler) setupSecondFactor(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != setupFactorPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current, digest, ok := h.authorizeSessionPost(w, r)
	if !ok {
		return
	}
	if !h.allowAttempts(h.setupAttempts, w, r) {
		return
	}
	h.mu.Lock()
	stored, found := h.sessions[digest]
	pending := stored.pending
	h.mu.Unlock()
	if !found || pending == nil || !h.now().Before(pending.expiresAt) {
		http.Redirect(w, r, setupPath, http.StatusSeeOther)
		return
	}
	if !pending.secondFactor.verify(r.PostForm.Get("totp_code"), h.now()) {
		h.renderFactor(w, http.StatusUnauthorized, current, pending,
			"动态验证码不正确。请确认验证器应用里的密钥与上一步显示的一致，并检查设备时间。")
		return
	}
	credential := admission.AdministratorCredential{
		Name: pending.name, PasswordHash: pending.passwordHash,
		TOTPSecret: encodeTOTPSecret(pending.secret), UpdatedAt: h.now(),
	}
	if err := h.accounts.SaveAdministrator(r.Context(), credential); err != nil {
		http.Error(w, "unable to store the administrator credential", http.StatusInternalServerError)
		return
	}
	updated, err := accountFromCredential(credential)
	if err != nil {
		http.Error(w, "unable to read back the stored credential", http.StatusInternalServerError)
		return
	}
	// Adopt the verifier that accepted the confirmation code, so the same code
	// cannot be replayed as a login inside its thirty second window.
	updated.secondFactor = pending.secondFactor
	h.mu.Lock()
	h.account = updated
	// Replacing the credentials ends every other management session and clears the
	// half-finished state from this one.
	for key := range h.sessions {
		if key != digest {
			delete(h.sessions, key)
		}
	}
	stored.pending = nil
	stored.mustInitialize = false
	stored.flash = &flashMessage{
		Kind:    "success",
		Message: "凭据已更新。下次登录请使用新的用户名、密码和动态验证码。",
	}
	h.sessions[digest] = stored
	h.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) renderFactor(
	w http.ResponseWriter,
	status int,
	current session,
	pending *pendingSetup,
	message string,
) {
	encoded := encodeTOTPSecret(pending.secret)
	h.renderStatus(w, status, "setup_factor.html", setupFactorView{
		CSRFToken: current.csrfToken, Name: pending.name,
		Secret: formatTOTPSecret(encoded), URI: totpProvisioningURI(pending.name, encoded),
		FirstRun: current.mustInitialize, Error: message,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.authorizeSessionPost(w, r)
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
	if current.mustInitialize {
		http.Redirect(w, r, setupPath, http.StatusSeeOther)
		return
	}
	accountState := h.currentAccount()
	view := dashboardView{
		CSRFToken: current.csrfToken, Flash: h.takeFlash(digest),
		AccountName: accountState.name, AccountUpdated: formatTime(accountState.updatedAt),
	}
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
			viewDevice := deviceView{
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
			}
			switch {
			case pending:
				item.PendingDevices = append(item.PendingDevices, viewDevice)
			case viewDevice.CanRename:
				item.ActiveDevices = append(item.ActiveDevices, viewDevice)
			default:
				item.PastDevices = append(item.PastDevices, viewDevice)
			}
		}
		view.Workspaces = append(view.Workspaces, item)
	}
	h.render(w, "dashboard.html", view)
}

// authorizeSessionPost validates a signed-in POST: method, session, origin and
// CSRF token. It deliberately does not require the credentials to be initialized,
// because replacing the default credentials and signing out both have to work from
// a session that still is not.
func (h *Handler) authorizeSessionPost(
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
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil || !h.validOrigin(r) ||
		subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf_token")),
			[]byte(current.csrfToken)) != 1 {
		http.Error(w, "request rejected", http.StatusForbidden)
		return session{}, [sha256.Size]byte{}, false
	}
	return current, digest, true
}

func (h *Handler) authorizeManagementPost(
	w http.ResponseWriter,
	r *http.Request,
) (session, [sha256.Size]byte, bool) {
	current, digest, ok := h.authorizeSessionPost(w, r)
	if !ok {
		return session{}, [sha256.Size]byte{}, false
	}
	if current.mustInitialize {
		http.Redirect(w, r, setupPath, http.StatusSeeOther)
		return session{}, [sha256.Size]byte{}, false
	}
	if !h.managementActions.Allow(base64.RawURLEncoding.EncodeToString(digest[:]), h.now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many actions", http.StatusTooManyRequests)
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
	message := "用户名、密码或动态验证码不正确。应急登录码只在下发后的十分钟内可用，且只能使用一次。"
	if !h.currentAccount().initialized {
		message = "初始账号或密码不正确。首次使用请按部署说明用初始账号登录，" +
			"登录后必须立即设置新口令并绑定动态验证码。"
	}
	h.renderStatus(w, http.StatusUnauthorized, "login.html", h.loginView(message))
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
		// Chromium derives the Origin header of a navigation request (which is what a
		// form submission is) from the referrer, so "no-referrer" makes every form
		// post arrive as origin null and validOrigin rejects the login before the
		// credentials are even read. "same-origin" keeps referrers inside this
		// console and nothing cross-origin, which is the property that matters here.
		w.Header().Set("Referrer-Policy", "same-origin")
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
