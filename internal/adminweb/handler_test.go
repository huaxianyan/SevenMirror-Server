package adminweb

import (
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/adminservice"
	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

type fixedStore struct {
	workspaces       []admission.WorkspaceSummary
	devices          map[admission.WorkspaceID][]admission.DeviceSummary
	renamedReference string
	renamedName      string
	pairingName      string
}

func (s fixedStore) ListWorkspaces(context.Context) ([]admission.WorkspaceSummary, error) {
	return s.workspaces, nil
}

func (s fixedStore) ListDevices(
	_ context.Context,
	workspaceID admission.WorkspaceID,
) ([]admission.DeviceSummary, error) {
	return s.devices[workspaceID], nil
}

func (s *fixedStore) IssuePairingCode(
	_ context.Context,
	_ admission.WorkspaceID,
	_ admission.DeviceType,
	deviceName string,
	now time.Time,
	_ time.Duration,
) (adminservice.PairingCode, error) {
	s.pairingName = deviceName
	return adminservice.PairingCode{Code: "JOIN-CODE", ExpiresAt: now.Add(10 * time.Minute)}, nil
}

func (s fixedStore) ApproveDevice(
	context.Context,
	admission.WorkspaceID,
	string,
	time.Time,
) (admission.ApprovedMembership, error) {
	return admission.ApprovedMembership{}, nil
}

func (s *fixedStore) RenameDevice(
	_ context.Context,
	_ admission.WorkspaceID,
	deviceReference string,
	displayName string,
	_ time.Time,
) (admission.RenamedDevice, error) {
	s.renamedReference = deviceReference
	s.renamedName = displayName
	return admission.RenamedDevice{}, nil
}

func (s fixedStore) ChangeDeviceAccess(
	context.Context,
	admission.WorkspaceID,
	string,
	adminservice.DeviceAccessAction,
	time.Time,
) (admission.RevokedDevice, error) {
	return admission.RevokedDevice{}, nil
}

// memoryAccountStore stands in for the registry row. has stays false until the
// console stores a credential, which is the state a fresh deployment starts in.
type memoryAccountStore struct {
	credential admission.AdministratorCredential
	saves      int
	has        bool
}

func (s *memoryAccountStore) LoadAdministrator(
	context.Context,
) (admission.AdministratorCredential, bool, error) {
	return s.credential, s.has, nil
}

func (s *memoryAccountStore) SaveAdministrator(
	_ context.Context,
	credential admission.AdministratorCredential,
) error {
	if len(credential.Name) == 0 || len(credential.PasswordHash) == 0 ||
		len(credential.TOTPSecret) == 0 {
		return errors.New("incomplete administrator credential")
	}
	s.credential = credential
	s.has = true
	s.saves++
	return nil
}

func storedAccountStore(t *testing.T) *memoryAccountStore {
	t.Helper()
	return &memoryAccountStore{
		credential: testCredential(t, testStoredName, testPassword, testSecret),
		has:        true,
	}
}

// countingRandom yields a fresh byte sequence on every read, so the workspace
// reference key and every session token come out distinct without real entropy.
type countingRandom struct{ next byte }

func (r *countingRandom) Read(buffer []byte) (int, error) {
	for index := range buffer {
		r.next++
		buffer[index] = r.next
	}
	return len(buffer), nil
}

// newTestHandler builds a console whose clock the test owns, so the rate limiter's
// window and the TOTP time step both move when the test says they do.
func newTestHandler(t *testing.T, accounts AccountStore, moment *time.Time) http.Handler {
	t.Helper()
	handler, err := NewHandler(&fixedStore{}, accounts, HandlerConfig{
		RecoveryCode:   []byte("recovery-code-for-tests"),
		ExpectedOrigin: "http://127.0.0.1:8081",
		Now:            func() time.Time { return *moment },
		Random:         &countingRandom{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// wrongSecondFactor returns a code the verifier rejects in every step it accepts,
// so a refusal cannot be confused with a coincidental match.
func wrongSecondFactor(secret []byte, moment time.Time) string {
	current := totpCounter(moment)
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		accepted := false
		for delta := int64(-totpSkewSteps); delta <= totpSkewSteps; delta++ {
			if candidate == totpCode(secret, current+delta) {
				accepted = true
			}
		}
		if !accepted {
			return candidate
		}
	}
	return ""
}

func TestAdministratorLogsInOnceAndSeesDeviceStatusWithoutInternalIdentifiers(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	approved := now.Add(time.Minute)
	lastAuthenticated := now.Add(2 * time.Minute)
	lastActivity := now.Add(3 * time.Minute)
	var workspaceID admission.WorkspaceID
	copy(workspaceID[:], []byte("workspace-id-001"))
	store := &fixedStore{
		workspaces: []admission.WorkspaceSummary{{ID: workspaceID, CreatedAt: now}},
		devices: map[admission.WorkspaceID][]admission.DeviceSummary{
			workspaceID: {
				{
					Reference: "secret-reference", DeviceType: admission.DeviceChrome,
					DeviceName: "工作电脑", MembershipState: "approved", RegisteredAt: now,
					ApprovedAt: &approved, LastAuthenticatedAt: &lastAuthenticated,
					LastActivityAt: &lastActivity,
				},
				{
					Reference: "pending-reference", DeviceType: admission.DeviceAndroid,
					DeviceName: "新手机", MembershipState: "pending_approval", RegisteredAt: now,
				},
				{
					Reference: "removed-reference", DeviceType: admission.DeviceChrome,
					DeviceName: "旧电脑", MembershipState: "approved", RegisteredAt: now,
					Revoked: true, RevokedAt: &approved,
				},
			},
		},
	}
	secret, err := parseTOTPSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	loginMoment := now.Add(3 * time.Minute)
	validSecondFactor := totpCode(secret, totpCounter(loginMoment))
	invalidSecondFactor := "000000"
	if validSecondFactor == invalidSecondFactor {
		invalidSecondFactor = "111111"
	}
	handler, err := NewHandler(store, storedAccountStore(t), HandlerConfig{
		RecoveryCode:   []byte("recovery-code-for-tests"),
		ExpectedOrigin: "http://127.0.0.1:8081",
		Now:            func() time.Time { return loginMoment },
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x42}, 96)),
	})
	if err != nil {
		t.Fatal(err)
	}

	unauthenticated := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/", nil)
	unauthenticated.Host = "127.0.0.1:8081"
	unauthenticatedResult := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedResult, unauthenticated)
	if unauthenticatedResult.Code != http.StatusSeeOther ||
		unauthenticatedResult.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated response=%d location=%q",
			unauthenticatedResult.Code, unauthenticatedResult.Header().Get("Location"))
	}

	wrongPassword := postForm(t, handler, "/login", url.Values{
		"username": {"operator"}, "password": {"not the password"},
		"totp_code": {validSecondFactor},
	}, nil)
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password response=%d", wrongPassword.Code)
	}
	wrongSecondFactor := postForm(t, handler, "/login", url.Values{
		"username": {"operator"}, "password": {testPassword},
		"totp_code": {invalidSecondFactor},
	}, nil)
	if wrongSecondFactor.Code != http.StatusUnauthorized {
		t.Fatalf("wrong second factor response=%d", wrongSecondFactor.Code)
	}

	loginResult := postForm(t, handler, "/login", url.Values{
		"username": {"operator"}, "password": {testPassword},
		"totp_code": {validSecondFactor},
	}, nil)
	if loginResult.Code != http.StatusSeeOther {
		t.Fatalf("login response=%d body=%s", loginResult.Code, loginResult.Body.String())
	}
	cookies := loginResult.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookies=%+v", cookies)
	}

	// A second factor belongs to its time step: presenting the same code again must
	// not start a second session.
	replayed := postForm(t, handler, "/login", url.Values{
		"username": {"operator"}, "password": {testPassword},
		"totp_code": {validSecondFactor},
	}, nil)
	if replayed.Code != http.StatusUnauthorized {
		t.Fatalf("replayed second factor response=%d", replayed.Code)
	}

	dashboardRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/", nil)
	dashboardRequest.Host = "127.0.0.1:8081"
	dashboardRequest.AddCookie(cookies[0])
	dashboardResult := httptest.NewRecorder()
	handler.ServeHTTP(dashboardResult, dashboardRequest)
	body, _ := io.ReadAll(dashboardResult.Result().Body)
	text := string(body)
	if dashboardResult.Code != http.StatusOK || !strings.Contains(text, "工作电脑") ||
		!strings.Contains(text, "新手机") || !strings.Contains(text, "旧电脑") ||
		!strings.Contains(text, "刚刚活动") || strings.Contains(text, "secret-reference") ||
		strings.Contains(text, "pending-reference") || strings.Contains(text, "removed-reference") ||
		strings.Contains(text, "workspace-id-001") {
		t.Fatalf("dashboard response=%d body=%s", dashboardResult.Code, text)
	}
	if pendingIndex, activeIndex := strings.Index(text, ">待处理申请</h3>"), strings.Index(text, ">已接入设备</h3>"); pendingIndex < 0 || activeIndex < 0 || pendingIndex >= activeIndex ||
		!strings.Contains(text, "添加设备") || !strings.Contains(text, "部署与维护") ||
		!strings.Contains(text, `<details class="device-group history-group">`) {
		t.Fatalf("dashboard does not prioritize device tasks: %s", text)
	}
	// A referrer policy of "no-referrer" makes Chromium derive a null Origin for
	// the form posts this console depends on, so the value is pinned here instead
	// of being left to a later tightening pass.
	if dashboardResult.Header().Get("Content-Security-Policy") == "" ||
		dashboardResult.Header().Get("X-Frame-Options") != "DENY" ||
		dashboardResult.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("security headers=%v", dashboardResult.Header())
	}
	csrf := firstCapture(t, text, `name="csrf_token" value="([^"]+)"`)
	workspaceReference := firstCapture(t, text, `name="workspace_ref" value="([^"]+)"`)
	deviceReference := firstCapture(t, text,
		`(?s)action="/actions/rename".*?name="device_ref" value="([^"]+)"`)
	renameResult := postForm(t, handler, "/actions/rename", url.Values{
		"csrf_token": {csrf}, "workspace_ref": {workspaceReference},
		"device_ref": {deviceReference}, "new_name": {"客厅电脑"}, "confirm": {"yes"},
	}, cookies[0])
	if renameResult.Code != http.StatusSeeOther || store.renamedReference != "secret-reference" ||
		store.renamedName != "客厅电脑" {
		t.Fatalf("rename response=%d reference=%q name=%q", renameResult.Code,
			store.renamedReference, store.renamedName)
	}
	// The console no longer names the device: the client supplies the name when it
	// joins, so the issued code must not carry a bound name the client would then
	// have to reproduce byte for byte. The stale field is sent on purpose to pin
	// that a leftover form value cannot reintroduce one.
	pairingResult := postForm(t, handler, "/actions/pairing-code", url.Values{
		"csrf_token": {csrf}, "workspace_ref": {workspaceReference},
		"device_type": {"android"}, "device_name": {"手机"},
	}, cookies[0])
	if pairingResult.Code != http.StatusSeeOther || store.pairingName != "" {
		t.Fatalf("pairing response=%d boundName=%q body=%s", pairingResult.Code,
			store.pairingName, pairingResult.Body.String())
	}
	flashRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/", nil)
	flashRequest.Host = "127.0.0.1:8081"
	flashRequest.AddCookie(cookies[0])
	flashResult := httptest.NewRecorder()
	handler.ServeHTTP(flashResult, flashRequest)
	if flashBody := flashResult.Body.String(); !strings.Contains(flashBody, "JOIN-CODE") ||
		strings.Contains(flashBody, "workspace-id-001") {
		t.Fatalf("pairing flash body=%s", flashBody)
	}

	logoutWithoutCSRF := postForm(t, handler, "/logout", nil, cookies[0])
	if logoutWithoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF response=%d", logoutWithoutCSRF.Code)
	}
}

func TestAdministratorRecoveryCodeIsSingleUseAndExpires(t *testing.T) {
	secret, err := parseTOTPSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	moment := time.UnixMilli(1_800_000_000_000)
	handler, err := NewHandler(&fixedStore{}, storedAccountStore(t), HandlerConfig{
		RecoveryCode:   []byte("recovery-code-for-tests"),
		ExpectedOrigin: "http://127.0.0.1:8081",
		Now:            func() time.Time { return moment },
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x24}, 512)),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The recovery code stands in for both factors, so an operator who lost the
	// authenticator device can still reach the console.
	issued := postForm(t, handler, "/login", url.Values{
		"recovery_code": {"recovery-code-for-tests"},
	}, nil)
	if issued.Code != http.StatusSeeOther {
		t.Fatalf("recovery login response=%d body=%s", issued.Code, issued.Body.String())
	}
	replayed := postForm(t, handler, "/login", url.Values{
		"recovery_code": {"recovery-code-for-tests"},
	}, nil)
	if replayed.Code != http.StatusUnauthorized {
		t.Fatalf("replayed recovery code response=%d", replayed.Code)
	}
	wrong := postForm(t, handler, "/login", url.Values{
		"recovery_code": {"some other code"},
	}, nil)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong recovery code response=%d", wrong.Code)
	}

	// A code kept from an earlier start is refused once the ten minute window passed,
	// while the account and second factor keep working without a restart.
	moment = moment.Add(11 * time.Minute)
	late := postForm(t, handler, "/login", url.Values{
		"recovery_code": {"recovery-code-for-tests"},
	}, nil)
	if late.Code != http.StatusUnauthorized {
		t.Fatalf("expired recovery code response=%d", late.Code)
	}
	secondFactor := totpCode(secret, totpCounter(moment))
	account := postForm(t, handler, "/login", url.Values{
		"username": {"operator"}, "password": {testPassword}, "totp_code": {secondFactor},
	}, nil)
	if account.Code != http.StatusSeeOther {
		t.Fatalf("account login response=%d body=%s", account.Code, account.Body.String())
	}
}

func firstCapture(t *testing.T, value string, expression string) string {
	t.Helper()
	match := regexp.MustCompile(expression).FindStringSubmatch(value)
	if len(match) != 2 {
		t.Fatalf("pattern %q not found", expression)
	}
	return match[1]
}

func postForm(
	t *testing.T,
	handler http.Handler,
	path string,
	values url.Values,
	cookie *http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081"+path,
		strings.NewReader(values.Encode()))
	request.Host = "127.0.0.1:8081"
	request.RemoteAddr = "127.0.0.1:32100"
	request.Header.Set("Origin", "http://127.0.0.1:8081")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	return result
}

func getPage(
	t *testing.T,
	handler http.Handler,
	path string,
	cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081"+path, nil)
	request.Host = "127.0.0.1:8081"
	request.RemoteAddr = "127.0.0.1:32100"
	for _, cookie := range cookies {
		if cookie != nil {
			request.AddCookie(cookie)
		}
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	return result
}

// The default account opens a session and nothing else: every management route
// redirects back to the credential setup until an administrator replaces it.
func TestFreshConsoleForcesCredentialSetupBeforeManaging(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	accounts := &memoryAccountStore{}
	handler := newTestHandler(t, accounts, &moment)

	loginPage := getPage(t, handler, "/login", nil)
	if loginPage.Code != http.StatusOK || !strings.Contains(loginPage.Body.String(), "这是首次使用") ||
		strings.Contains(loginPage.Body.String(), `name="totp_code"`) {
		t.Fatalf("first-run login page=%d body=%s", loginPage.Code, loginPage.Body.String())
	}

	login := postForm(t, handler, "/login", url.Values{
		"username": {DefaultAdministratorName}, "password": {defaultAdministratorPassword},
	}, nil)
	cookies := login.Result().Cookies()
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != setupPath ||
		len(cookies) != 1 {
		t.Fatalf("default login=%d location=%q cookies=%v",
			login.Code, login.Header().Get("Location"), cookies)
	}

	setupPage := getPage(t, handler, setupPath, cookies[0])
	if setupPage.Code != http.StatusOK {
		t.Fatalf("setup page=%d body=%s", setupPage.Code, setupPage.Body.String())
	}
	csrf := firstCapture(t, setupPage.Body.String(), `name="csrf_token" value="([^"]+)"`)
	dashboard := getPage(t, handler, "/", cookies[0])
	if dashboard.Code != http.StatusSeeOther || dashboard.Header().Get("Location") != setupPath {
		t.Fatalf("dashboard before setup=%d location=%q",
			dashboard.Code, dashboard.Header().Get("Location"))
	}
	action := postForm(t, handler, "/actions/pairing-code", url.Values{
		"csrf_token": {csrf}, "workspace_ref": {"whatever"}, "device_type": {"android"},
	}, cookies[0])
	if action.Code != http.StatusSeeOther || action.Header().Get("Location") != setupPath {
		t.Fatalf("management action before setup=%d location=%q body=%s",
			action.Code, action.Header().Get("Location"), action.Body.String())
	}

	moment = moment.Add(time.Minute)
	step := postForm(t, handler, setupPath, url.Values{
		"csrf_token": {csrf}, "username": {"neko7ina"},
		"password": {testPassword}, "password_confirm": {testPassword},
	}, cookies[0])
	if step.Code != http.StatusOK || !strings.Contains(step.Body.String(), "otpauth://totp/") {
		t.Fatalf("setup step one=%d body=%s", step.Code, step.Body.String())
	}
	displayed := firstCapture(t, step.Body.String(), `<code class="secret">([A-Z2-7 ]+)</code>`)
	secret, err := parseTOTPSecret(displayed)
	if err != nil {
		t.Fatalf("displayed secret %q: %v", displayed, err)
	}

	moment = moment.Add(time.Minute)
	wrong := postForm(t, handler, setupFactorPath, url.Values{
		"csrf_token": {csrf}, "totp_code": {wrongSecondFactor(secret, moment)},
	}, cookies[0])
	if wrong.Code != http.StatusUnauthorized || accounts.has {
		t.Fatalf("wrong confirmation=%d stored=%v", wrong.Code, accounts.has)
	}

	moment = moment.Add(time.Minute)
	setupCode := totpCode(secret, totpCounter(moment))
	confirmed := postForm(t, handler, setupFactorPath, url.Values{
		"csrf_token": {csrf}, "totp_code": {setupCode},
	}, cookies[0])
	if confirmed.Code != http.StatusSeeOther || confirmed.Header().Get("Location") != "/" {
		t.Fatalf("confirmation=%d location=%q body=%s",
			confirmed.Code, confirmed.Header().Get("Location"), confirmed.Body.String())
	}
	if !accounts.has || accounts.credential.Name != "neko7ina" || accounts.saves != 1 {
		t.Fatalf("stored credential=%+v saves=%d", accounts.credential, accounts.saves)
	}
	stored, err := accountFromCredential(accounts.credential)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.initialized || !stored.passwordMatches(testPassword) {
		t.Fatal("the stored credential did not verify the password chosen during setup")
	}

	// The code that finished the setup belongs to the live verifier now, so it
	// cannot be presented again as a login inside the same time step.
	replayedSetup := postForm(t, handler, "/login", url.Values{
		"username": {"neko7ina"}, "password": {testPassword}, "totp_code": {setupCode},
	}, nil)
	if replayedSetup.Code != http.StatusUnauthorized {
		t.Fatalf("the setup confirmation code signed in: %d", replayedSetup.Code)
	}
	if after := getPage(t, handler, "/", cookies[0]); after.Code != http.StatusOK {
		t.Fatalf("dashboard after setup=%d body=%s", after.Code, after.Body.String())
	}

	moment = moment.Add(2 * time.Minute)
	stale := postForm(t, handler, "/login", url.Values{
		"username": {DefaultAdministratorName}, "password": {defaultAdministratorPassword},
	}, nil)
	if stale.Code != http.StatusUnauthorized {
		t.Fatalf("the default account still signed in after setup: %d", stale.Code)
	}
	moment = moment.Add(time.Minute)
	fresh := postForm(t, handler, "/login", url.Values{
		"username": {"neko7ina"}, "password": {testPassword},
		"totp_code": {totpCode(secret, totpCounter(moment))},
	}, nil)
	if fresh.Code != http.StatusSeeOther || fresh.Header().Get("Location") != "/" {
		t.Fatalf("new credential login=%d location=%q body=%s",
			fresh.Code, fresh.Header().Get("Location"), fresh.Body.String())
	}
}

func TestSetupRejectsWeakCredentialsWithoutStoringAnything(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	accounts := &memoryAccountStore{}
	handler := newTestHandler(t, accounts, &moment)

	login := postForm(t, handler, "/login", url.Values{
		"username": {DefaultAdministratorName}, "password": {defaultAdministratorPassword},
	}, nil)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%v", cookies)
	}
	csrf := firstCapture(t, getPage(t, handler, setupPath, cookies[0]).Body.String(),
		`name="csrf_token" value="([^"]+)"`)

	for name, values := range map[string]url.Values{
		"short password": {
			"username": {"neko7ina"}, "password": {"short"}, "password_confirm": {"short"},
		},
		"mismatched confirmation": {
			"username": {"neko7ina"}, "password": {testPassword},
			"password_confirm": {testPassword + "-typo"},
		},
		"default password reused": {
			"username": {"neko7ina"}, "password": {defaultAdministratorPassword},
			"password_confirm": {defaultAdministratorPassword},
		},
		"name with a space": {
			"username": {"two words"}, "password": {testPassword},
			"password_confirm": {testPassword},
		},
		"empty name": {
			"username": {"  "}, "password": {testPassword}, "password_confirm": {testPassword},
		},
	} {
		values.Set("csrf_token", csrf)
		if result := postForm(t, handler, setupPath, values, cookies[0]); result.Code != http.StatusBadRequest {
			t.Fatalf("%s response=%d body=%s", name, result.Code, result.Body.String())
		}
		if accounts.has {
			t.Fatalf("%s stored a credential", name)
		}
	}

	accepted := postForm(t, handler, setupPath, url.Values{
		"csrf_token": {csrf}, "username": {"neko7ina"},
		"password": {testPassword}, "password_confirm": {testPassword},
	}, cookies[0])
	if accepted.Code != http.StatusOK || accounts.has {
		t.Fatalf("compliant setup=%d stored=%v", accepted.Code, accounts.has)
	}
}

// Negotiating the password policy is not a credential guess. The setup window is
// separate from the login window, so a few rejected submissions must not lock the
// administrator out of their own first sign-in.
func TestSetupAttemptsDoNotConsumeTheLoginWindow(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	accounts := &memoryAccountStore{}
	handler := newTestHandler(t, accounts, &moment)

	login := postForm(t, handler, "/login", url.Values{
		"username": {DefaultAdministratorName}, "password": {defaultAdministratorPassword},
	}, nil)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%v", cookies)
	}
	csrf := firstCapture(t, getPage(t, handler, setupPath, cookies[0]).Body.String(),
		`name="csrf_token" value="([^"]+)"`)

	for attempt := 1; attempt <= 6; attempt++ {
		result := postForm(t, handler, setupPath, url.Values{
			"csrf_token": {csrf}, "username": {"neko7ina"},
			"password": {"short"}, "password_confirm": {"short"},
		}, cookies[0])
		if result.Code != http.StatusBadRequest {
			t.Fatalf("setup attempt %d response=%d", attempt, result.Code)
		}
	}
	if result := postForm(t, handler, "/login", url.Values{
		"username": {DefaultAdministratorName}, "password": {"not the password"},
	}, nil); result.Code != http.StatusUnauthorized {
		t.Fatalf("login after repeated setup attempts=%d", result.Code)
	}
	accepted := postForm(t, handler, setupPath, url.Values{
		"csrf_token": {csrf}, "username": {"neko7ina"},
		"password": {testPassword}, "password_confirm": {testPassword},
	}, cookies[0])
	if accepted.Code != http.StatusOK || accounts.has {
		t.Fatalf("compliant setup after repeated attempts=%d stored=%v body=%s",
			accepted.Code, accounts.has, accepted.Body.String())
	}
}

// A half-finished setup is abandoned rather than half applied, and the wizard
// starts again from the account name.
func TestExpiredPendingSetupRestartsTheWizard(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	accounts := &memoryAccountStore{}
	handler := newTestHandler(t, accounts, &moment)

	login := postForm(t, handler, "/login", url.Values{
		"username": {DefaultAdministratorName}, "password": {defaultAdministratorPassword},
	}, nil)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%v", cookies)
	}
	csrf := firstCapture(t, getPage(t, handler, setupPath, cookies[0]).Body.String(),
		`name="csrf_token" value="([^"]+)"`)
	moment = moment.Add(time.Minute)
	step := postForm(t, handler, setupPath, url.Values{
		"csrf_token": {csrf}, "username": {"neko7ina"},
		"password": {testPassword}, "password_confirm": {testPassword},
	}, cookies[0])
	displayed := firstCapture(t, step.Body.String(), `<code class="secret">([A-Z2-7 ]+)</code>`)
	secret, err := parseTOTPSecret(displayed)
	if err != nil {
		t.Fatal(err)
	}

	moment = moment.Add(setupPendingLifetime + time.Minute)
	late := postForm(t, handler, setupFactorPath, url.Values{
		"csrf_token": {csrf}, "totp_code": {totpCode(secret, totpCounter(moment))},
	}, cookies[0])
	if late.Code != http.StatusSeeOther || late.Header().Get("Location") != setupPath {
		t.Fatalf("expired confirmation=%d location=%q", late.Code, late.Header().Get("Location"))
	}
	if accounts.has {
		t.Fatal("an expired setup stored a credential")
	}
}

// Replacing the credentials ends every other management session, while the session
// that made the change keeps working.
func TestCredentialChangeEndsOtherSessions(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	handler := newTestHandler(t, storedAccountStore(t), &moment)
	secret := testSecretBytes(t)

	first := postForm(t, handler, "/login", url.Values{
		"username": {testStoredName}, "password": {testPassword},
		"totp_code": {totpCode(secret, totpCounter(moment))},
	}, nil)
	firstCookies := first.Result().Cookies()
	moment = moment.Add(time.Minute)
	second := postForm(t, handler, "/login", url.Values{
		"username": {testStoredName}, "password": {testPassword},
		"totp_code": {totpCode(secret, totpCounter(moment))},
	}, nil)
	secondCookies := second.Result().Cookies()
	if len(firstCookies) != 1 || len(secondCookies) != 1 ||
		firstCookies[0].Value == secondCookies[0].Value {
		t.Fatalf("expected two distinct sessions, got %v and %v", firstCookies, secondCookies)
	}

	csrf := firstCapture(t, getPage(t, handler, setupPath, firstCookies[0]).Body.String(),
		`name="csrf_token" value="([^"]+)"`)
	moment = moment.Add(time.Minute)
	step := postForm(t, handler, setupPath, url.Values{
		"csrf_token": {csrf}, "username": {testStoredName},
		"password": {"a brand new passphrase"}, "password_confirm": {"a brand new passphrase"},
	}, firstCookies[0])
	if step.Code != http.StatusOK {
		t.Fatalf("rotation step one=%d body=%s", step.Code, step.Body.String())
	}
	rotated := firstCapture(t, step.Body.String(), `<code class="secret">([A-Z2-7 ]+)</code>`)
	newSecret, err := parseTOTPSecret(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newSecret, secret) {
		t.Fatal("the rotation reused the previous authenticator secret")
	}
	moment = moment.Add(time.Minute)
	confirmed := postForm(t, handler, setupFactorPath, url.Values{
		"csrf_token": {csrf}, "totp_code": {totpCode(newSecret, totpCounter(moment))},
	}, firstCookies[0])
	if confirmed.Code != http.StatusSeeOther || confirmed.Header().Get("Location") != "/" {
		t.Fatalf("rotation confirmation=%d location=%q body=%s",
			confirmed.Code, confirmed.Header().Get("Location"), confirmed.Body.String())
	}
	if page := getPage(t, handler, "/", firstCookies[0]); page.Code != http.StatusOK {
		t.Fatalf("the session that rotated the credentials was ended: %d", page.Code)
	}
	stale := getPage(t, handler, "/", secondCookies[0])
	if stale.Code != http.StatusSeeOther || stale.Header().Get("Location") != "/login" {
		t.Fatalf("the other session survived the credential change: %d location=%q",
			stale.Code, stale.Header().Get("Location"))
	}
}

func TestRecoveryCodeStillRequiresSetupOnAFreshConsole(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	handler := newTestHandler(t, &memoryAccountStore{}, &moment)
	issued := postForm(t, handler, "/login", url.Values{
		"recovery_code": {"recovery-code-for-tests"},
	}, nil)
	if issued.Code != http.StatusSeeOther || issued.Header().Get("Location") != setupPath {
		t.Fatalf("recovery login on a fresh console=%d location=%q",
			issued.Code, issued.Header().Get("Location"))
	}
}

func TestRecoveryCodeReachesManagementOnAnInitializedConsole(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	handler := newTestHandler(t, storedAccountStore(t), &moment)
	issued := postForm(t, handler, "/login", url.Values{
		"recovery_code": {"recovery-code-for-tests"},
	}, nil)
	cookies := issued.Result().Cookies()
	if issued.Code != http.StatusSeeOther || issued.Header().Get("Location") != "/" ||
		len(cookies) != 1 {
		t.Fatalf("recovery login=%d location=%q cookies=%v",
			issued.Code, issued.Header().Get("Location"), cookies)
	}
	if page := getPage(t, handler, "/", cookies[0]); page.Code != http.StatusOK {
		t.Fatalf("dashboard through the recovery code=%d", page.Code)
	}
}

// A stored row the console cannot parse must stop the process instead of quietly
// falling back to the published default password.
func TestUnparsableStoredCredentialStopsTheConsole(t *testing.T) {
	for name, credential := range map[string]admission.AdministratorCredential{
		"bad hash": {
			Name: "operator", PasswordHash: "not-a-phc-string", TOTPSecret: testSecret,
		},
		"bad secret": {
			Name: "operator", PasswordHash: testPasswordHashString(t, testPassword),
			TOTPSecret: "not-base32-!!!",
		},
		"blank name": {
			Name: "  ", PasswordHash: testPasswordHashString(t, testPassword),
			TOTPSecret: testSecret,
		},
	} {
		accounts := &memoryAccountStore{credential: credential, has: true}
		if _, err := NewHandler(&fixedStore{}, accounts, HandlerConfig{
			ExpectedOrigin: "http://127.0.0.1:8081",
		}); err == nil {
			t.Fatalf("NewHandler accepted a credential with a %s", name)
		}
	}
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q not set in %v", name, cookies)
	return nil
}

// loginCookie signs in with the stored credential at the test's own moment, which
// is all the console tests below need from the sign-in flow.
func loginCookie(t *testing.T, handler http.Handler, moment time.Time) *http.Cookie {
	t.Helper()
	secret, err := parseTOTPSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	result := postForm(t, handler, "/login", url.Values{
		"username": {testStoredName}, "password": {testPassword},
		"totp_code": {totpCode(secret, totpCounter(moment))},
	}, nil)
	if result.Code != http.StatusSeeOther {
		t.Fatalf("login response=%d body=%s", result.Code, result.Body.String())
	}
	cookies := result.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies=%v", cookies)
	}
	return cookies[0]
}

// The console shows one panel at a time, chosen by the left navigation, and the
// display time zone applies to every time it prints. Both are view behaviour:
// neither changes what the server stores or what the devices send.
func TestConsoleSectionsAndDisplayTimeZone(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	var workspaceID admission.WorkspaceID
	copy(workspaceID[:], []byte("workspace-id-002"))
	store := &fixedStore{
		workspaces: []admission.WorkspaceSummary{{ID: workspaceID, CreatedAt: now}},
	}
	moment := now
	handler, err := NewHandler(store, storedAccountStore(t), HandlerConfig{
		RecoveryCode:   []byte("recovery-code-for-tests"),
		ExpectedOrigin: "http://127.0.0.1:8081",
		Now:            func() time.Time { return moment },
		Random:         &countingRandom{},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginCookie(t, handler, moment)
	utcStamp := now.UTC().Format("2006-01-02 15:04:05 -07:00")

	// The template escapes the "+" of a printed UTC offset, which a browser decodes
	// back, so every assertion below reads the rendered text rather than the bytes.
	devicesResult := getPage(t, handler, "/", cookie)
	devices := html.UnescapeString(devicesResult.Body.String())
	if devicesResult.Code != http.StatusOK || !strings.Contains(devices, ">待处理申请</h3>") ||
		!strings.Contains(devices, `href="/?section=settings"`) {
		t.Fatalf("devices panel=%d body=%s", devicesResult.Code, devices)
	}
	// The private space cannot be renamed and there is only ever one of them, so
	// the console no longer numbers it.
	if !strings.Contains(devices, "<h2>私有空间</h2>") || strings.Contains(devices, "私有空间 1") {
		t.Fatalf("private space heading: %s", devices)
	}
	// Times start on UTC, which is what the server and the clients record.
	if !strings.Contains(devices, utcStamp) {
		t.Fatalf("creation time is not printed in UTC: %s", devices)
	}

	// Each section is its own panel behind its own URL, and an unknown one lands on
	// the default rather than rendering an empty page.
	settingsResult := getPage(t, handler, "/?section=settings", cookie)
	if settings := html.UnescapeString(settingsResult.Body.String()); settingsResult.Code != http.StatusOK ||
		!strings.Contains(settings, `action="/actions/timezone"`) ||
		!strings.Contains(settings, `aria-current="page"`) ||
		strings.Contains(settings, ">待处理申请</h3>") {
		t.Fatalf("settings panel=%d body=%s", settingsResult.Code, settings)
	}
	fallback := html.UnescapeString(getPage(t, handler, "/?section=does-not-exist", cookie).Body.String())
	if !strings.Contains(fallback, ">待处理申请</h3>") {
		t.Fatalf("unknown section body=%s", fallback)
	}

	// Choosing a zone stores a cookie in this browser. It has to outlive the sign-in
	// and must not reach the registry, the session or any device.
	csrf := firstCapture(t, devices, `name="csrf_token" value="([^"]+)"`)
	changed := postForm(t, handler, "/actions/timezone", url.Values{
		"csrf_token": {csrf}, "timezone": {"Asia/Shanghai"},
	}, cookie)
	if changed.Code != http.StatusSeeOther || changed.Header().Get("Location") != "/?section=settings" {
		t.Fatalf("timezone response=%d location=%q body=%s", changed.Code,
			changed.Header().Get("Location"), changed.Body.String())
	}
	timezoneCookie := cookieNamed(t, changed.Result().Cookies(), timezoneCookieName)
	if timezoneCookie.Value != "Asia/Shanghai" || !timezoneCookie.HttpOnly ||
		timezoneCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("timezone cookie=%+v", timezoneCookie)
	}

	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	zoned := html.UnescapeString(getPage(t, handler, "/", cookie, timezoneCookie).Body.String())
	if !strings.Contains(zoned, now.In(shanghai).Format("2006-01-02 15:04:05 -07:00")) {
		t.Fatalf("display zone did not change formatting: %s", zoned)
	}
	if strings.Contains(zoned, utcStamp) {
		t.Fatalf("page still prints UTC after the zone changed: %s", zoned)
	}
	selected := html.UnescapeString(
		getPage(t, handler, "/?section=settings", cookie, timezoneCookie).Body.String())
	if !strings.Contains(selected, `value="Asia/Shanghai" selected`) {
		t.Fatalf("chosen zone is not selected: %s", selected)
	}

	// A name that is not a zone is refused instead of being written to the cookie.
	rejected := postForm(t, handler, "/actions/timezone", url.Values{
		"csrf_token": {csrf}, "timezone": {"Mars/Olympus"},
	}, cookie)
	if rejected.Code != http.StatusSeeOther || len(rejected.Result().Cookies()) != 0 {
		t.Fatalf("unknown zone response=%d cookies=%v", rejected.Code, rejected.Result().Cookies())
	}
	reported := html.UnescapeString(getPage(t, handler, "/?section=settings", cookie).Body.String())
	if !strings.Contains(reported, "没有这个时区") {
		t.Fatalf("unknown zone was not reported: %s", reported)
	}
}

// The brand is written "SevenMirror" in the console, the clients and the docs. A
// style rule used to upper-case it wherever it appeared as a label, so the one
// name read differently depending on where it showed up.
func TestConsoleStylesheetDoesNotUpperCaseTheBrand(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	handler := newTestHandler(t, storedAccountStore(t), &moment)
	stylesheet := getPage(t, handler, "/assets/admin.css", nil)
	if stylesheet.Code != http.StatusOK {
		t.Fatalf("stylesheet=%d", stylesheet.Code)
	}
	rule := firstCapture(t, stylesheet.Body.String(), `(?s)\.eyebrow\s*\{([^}]*)\}`)
	if strings.Contains(rule, "text-transform") {
		t.Fatalf("the brand label is restyled: .eyebrow {%s}", rule)
	}
}

// The name has to read as strongly in the console as it does in the extension's
// settings page, which draws it at 18px in bold. The console used to set it at
// .78rem with wide tracking, which looked thin beside the client, and the
// stylesheet turns font synthesis off, so a family without the declared weight
// would show the name at a regular stroke instead of thickening it. Both values
// are therefore part of the regression rather than styling taste.
func TestConsoleStylesheetKeepsTheBrandAsLegibleAsTheClient(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	handler := newTestHandler(t, storedAccountStore(t), &moment)
	stylesheet := getPage(t, handler, "/assets/admin.css", nil)
	if stylesheet.Code != http.StatusOK {
		t.Fatalf("stylesheet=%d", stylesheet.Code)
	}
	rule := firstCapture(t, stylesheet.Body.String(), `(?s)\.eyebrow\s*\{([^}]*)\}`)
	size, err := strconv.ParseFloat(firstCapture(t, rule, `font-size:\s*([0-9.]+)rem`), 64)
	if err != nil {
		t.Fatalf("brand size is not a rem value: .eyebrow {%s}", rule)
	}
	weight, err := strconv.Atoi(firstCapture(t, rule, `font-weight:\s*([0-9]+)`))
	if err != nil {
		t.Fatalf("brand weight is not numeric: .eyebrow {%s}", rule)
	}
	if size < 1.125 || weight < 700 {
		t.Fatalf("brand is thinner than the client wordmark: size=%grem weight=%d", size, weight)
	}
}

// The tab icon is served from the binary, and a favicon fetch is an image load, so
// the policy has to allow same-origin images or Chromium refuses to draw it and the
// tab falls back to a blank glyph. Both halves are pinned together on purpose:
// tightening img-src away again breaks the icon without failing anything else.
func TestConsoleFaviconIsServedAndAllowedByThePolicy(t *testing.T) {
	moment := time.UnixMilli(1_800_000_000_000)
	handler := newTestHandler(t, storedAccountStore(t), &moment)

	page := getPage(t, handler, "/assets/admin.css", nil)
	if policy := page.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "img-src 'self'") {
		t.Fatalf("the policy does not allow the favicon: %q", policy)
	}

	icon := getPage(t, handler, "/favicon.ico", nil)
	if icon.Code != http.StatusOK {
		t.Fatalf("favicon=%d", icon.Code)
	}
	if contentType := icon.Header().Get("Content-Type"); contentType != "image/x-icon" {
		t.Fatalf("favicon content type=%q", contentType)
	}
	body, _ := io.ReadAll(icon.Result().Body)
	if len(body) < 6 || string(body[:4]) != "\x00\x00\x01\x00" {
		t.Fatalf("favicon is not an ICO: %q", body)
	}
	if frames := int(body[4]) | int(body[5])<<8; frames != 3 {
		t.Fatalf("favicon carries %d frames, expected 16/32/48", frames)
	}

	// Chromium only asks for /favicon.ico unasked when the page declares nothing, so
	// the templates have to point at it rather than relying on the default request.
	login := getPage(t, handler, "/login", nil)
	if !strings.Contains(login.Body.String(), `rel="icon" href="/favicon.ico"`) {
		t.Fatalf("the console templates do not link the icon: %s", login.Body.String())
	}
}
