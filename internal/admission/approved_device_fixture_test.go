package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"time"

	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
)

// registerApprovedTestDevice is a test-only fixture for tests whose subject is
// an already authority-approved device rather than the membership HTTP flow.
func registerApprovedTestDevice(
	ctx context.Context,
	store *Store,
	input Registration,
) (RegisteredDevice, error) {
	digest := bytes.Repeat([]byte{0x91}, sha256.Size)
	secret := bytes.Repeat([]byte{0x92}, sha256.Size)
	device, err := store.RegisterPending(ctx, input, func(WorkspaceID, DeviceID) (PendingChallenge, error) {
		return PendingChallenge{
			Digest: digest, Secret: secret, ExpiresAt: input.Now.Add(5 * time.Minute),
		}, nil
	})
	if err != nil {
		return RegisteredDevice{}, err
	}
	if err := store.CompletePendingIdentityProof(ctx, PendingIdentityProof{
		WorkspaceID: device.WorkspaceID, DeviceID: device.DeviceID, AuthToken: device.AuthToken,
		ChallengeDigest: digest, ChallengeSecret: secret, Now: input.Now.Add(time.Second),
	}); err != nil {
		return RegisteredDevice{}, err
	}
	roles := []membershipv1.DeviceRole{
		membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS,
		membershipv1.DeviceRole_DEVICE_ROLE_INVOKE_NOTIFICATION_ACTIONS,
	}
	if input.DeviceType == DeviceAndroid {
		roles = []membershipv1.DeviceRole{
			membershipv1.DeviceRole_DEVICE_ROLE_SEND_NOTIFICATIONS,
		}
	}
	_, err = store.ApprovePendingMembership(ctx, ApprovePendingDevice{
		WorkspaceID: device.WorkspaceID, DeviceReference: deviceReference(device.WorkspaceID, device.DeviceID),
		Roles: roles, AuthorityPrivateKey: testAuthorityPrivateKey(), Now: input.Now.Add(2 * time.Second),
	})
	if err != nil {
		return RegisteredDevice{}, err
	}
	return device, nil
}
