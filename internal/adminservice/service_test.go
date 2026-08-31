package adminservice

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/membershipcodec"
)

func TestProductDeviceAdmissionApprovesFixedRolesThenRejectsAndRemoves(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := admission.Open(ctx, filepath.Join(directory, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority, err := membership.GenerateAuthority(filepath.Join(directory, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_000_000)
	workspaceID, err := store.CreateWorkspace(ctx, authority.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, filepath.Join(directory, "authority"))
	if err != nil {
		t.Fatal(err)
	}

	chrome := registerPendingApproval(t, ctx, service, store, workspaceID,
		admission.DeviceChrome, "工作电脑", now)
	devices, err := service.ListDevices(ctx, workspaceID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("pending devices=%+v error=%v", devices, err)
	}
	approved, err := service.ApproveDevice(ctx, workspaceID, devices[0].Reference, now.Add(time.Minute))
	if err != nil || approved.RosterEpoch != 1 {
		t.Fatalf("approved=%+v error=%v", approved, err)
	}
	state, err := store.ReadMembershipState(ctx, workspaceID, chrome.DeviceID, chrome.AuthToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := membershipcodec.DecodeSignedDeviceCertificate(
		state.SignedCertificate, authority.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	roles := certificate.GetCertificate().GetRoles()
	if len(roles) != 2 ||
		roles[0] != membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS ||
		roles[1] != membershipv1.DeviceRole_DEVICE_ROLE_INVOKE_NOTIFICATION_ACTIONS {
		t.Fatalf("Chrome roles=%v", roles)
	}

	registerPendingApproval(t, ctx, service, store, workspaceID,
		admission.DeviceAndroid, "备用手机", now.Add(2*time.Minute))
	devices, err = service.ListDevices(ctx, workspaceID)
	if err != nil || len(devices) != 2 {
		t.Fatalf("devices before rejection=%+v error=%v", devices, err)
	}
	var pendingReference string
	for _, device := range devices {
		if device.DeviceName == "备用手机" {
			pendingReference = device.Reference
		}
	}
	if _, err := service.ChangeDeviceAccess(
		ctx, workspaceID, pendingReference, RejectPending, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	devices, _ = service.ListDevices(ctx, workspaceID)
	if !deviceWithName(devices, "备用手机").Revoked ||
		deviceWithName(devices, "备用手机").ApprovedAt != nil {
		t.Fatalf("rejected device=%+v", deviceWithName(devices, "备用手机"))
	}

	chromeSummary := deviceWithName(devices, "工作电脑")
	removed, err := service.ChangeDeviceAccess(
		ctx, workspaceID, chromeSummary.Reference, RemoveApproved, now.Add(4*time.Minute))
	if err != nil || !removed.Changed || removed.RosterEpoch != 2 {
		t.Fatalf("removed=%+v error=%v", removed, err)
	}
	if authorized, err := store.IsDeviceAuthorized(ctx, workspaceID, chrome.DeviceID); err != nil || authorized {
		t.Fatalf("removed device authorized=%v error=%v", authorized, err)
	}
}

func registerPendingApproval(
	t *testing.T,
	ctx context.Context,
	service *Service,
	store *admission.Store,
	workspaceID admission.WorkspaceID,
	deviceType admission.DeviceType,
	deviceName string,
	now time.Time,
) admission.RegisteredDevice {
	t.Helper()
	issued, err := service.IssuePairingCode(
		ctx, workspaceID, deviceType, deviceName, now, DefaultPairingCodeLifetime)
	if err != nil {
		t.Fatal(err)
	}
	challengeDigest := bytes.Repeat([]byte{0x31}, sha256.Size)
	challengeSecret := bytes.Repeat([]byte{0x42}, sha256.Size)
	publicKey := elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx,
		elliptic.P256().Params().Gy)
	registered, err := store.RegisterPending(ctx, admission.Registration{
		PairingCode: issued.Code, DeviceType: deviceType, DeviceName: deviceName,
		E2EEPublicKey: publicKey, Now: now,
	}, func(admission.WorkspaceID, admission.DeviceID) (admission.PendingChallenge, error) {
		return admission.PendingChallenge{
			Digest: challengeDigest, Secret: challengeSecret,
			ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePendingIdentityProof(ctx, admission.PendingIdentityProof{
		WorkspaceID: workspaceID, DeviceID: registered.DeviceID,
		AuthToken: registered.AuthToken, ChallengeDigest: challengeDigest,
		ChallengeSecret: challengeSecret, Now: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	return registered
}

func deviceWithName(devices []admission.DeviceSummary, name string) admission.DeviceSummary {
	for _, device := range devices {
		if device.DeviceName == name {
			return device
		}
	}
	return admission.DeviceSummary{}
}
