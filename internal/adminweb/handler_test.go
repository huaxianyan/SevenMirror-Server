package adminweb

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

type fixedStore struct {
	workspaces []admission.WorkspaceSummary
	devices    map[admission.WorkspaceID][]admission.DeviceSummary
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

func TestAdministratorLogsInOnceAndSeesDeviceStatusWithoutInternalIdentifiers(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	approved := now.Add(time.Minute)
	lastAuthenticated := now.Add(2 * time.Minute)
	lastActivity := now.Add(3 * time.Minute)
	var workspaceID admission.WorkspaceID
	copy(workspaceID[:], []byte("workspace-id-001"))
	store := fixedStore{
		workspaces: []admission.WorkspaceSummary{{ID: workspaceID, CreatedAt: now}},
		devices: map[admission.WorkspaceID][]admission.DeviceSummary{
			workspaceID: {{
				Reference: "secret-reference", DeviceType: admission.DeviceChrome,
				DeviceName: "工作电脑", MembershipState: "approved", RegisteredAt: now,
				ApprovedAt: &approved, LastAuthenticatedAt: &lastAuthenticated,
				LastActivityAt: &lastActivity,
			}},
		},
	}
	handler, err := NewHandler(store, HandlerConfig{
		LoginCode: []byte("correct-login-code"), ExpectedOrigin: "http://127.0.0.1:8081",
		Now:    func() time.Time { return now.Add(3 * time.Minute) },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
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

	loginResult := postForm(t, handler, "/login", url.Values{
		"login_code": {"correct-login-code"},
	}, nil)
	if loginResult.Code != http.StatusSeeOther {
		t.Fatalf("login response=%d body=%s", loginResult.Code, loginResult.Body.String())
	}
	cookies := loginResult.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookies=%+v", cookies)
	}

	reused := postForm(t, handler, "/login", url.Values{
		"login_code": {"correct-login-code"},
	}, nil)
	if reused.Code != http.StatusUnauthorized {
		t.Fatalf("reused login response=%d", reused.Code)
	}

	dashboardRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/", nil)
	dashboardRequest.Host = "127.0.0.1:8081"
	dashboardRequest.AddCookie(cookies[0])
	dashboardResult := httptest.NewRecorder()
	handler.ServeHTTP(dashboardResult, dashboardRequest)
	body, _ := io.ReadAll(dashboardResult.Result().Body)
	text := string(body)
	if dashboardResult.Code != http.StatusOK || !strings.Contains(text, "工作电脑") ||
		!strings.Contains(text, "刚刚活动") || strings.Contains(text, "secret-reference") ||
		strings.Contains(text, "workspace-id-001") {
		t.Fatalf("dashboard response=%d body=%s", dashboardResult.Code, text)
	}
	if dashboardResult.Header().Get("Content-Security-Policy") == "" ||
		dashboardResult.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers=%v", dashboardResult.Header())
	}

	logoutWithoutCSRF := postForm(t, handler, "/logout", nil, cookies[0])
	if logoutWithoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF response=%d", logoutWithoutCSRF.Code)
	}
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
