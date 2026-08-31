package adminservice

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
)

const pairingCodeLifetime = 10 * time.Minute

var ErrInvalidDeviceState = errors.New("device is not in the required state")

type Service struct {
	store                 *admission.Store
	authorityKeyDirectory string
}

type PairingCode struct {
	Code      string
	ExpiresAt time.Time
}

type DeviceAccessAction string

const (
	RejectPending  DeviceAccessAction = "reject-pending"
	RemoveApproved DeviceAccessAction = "remove-approved"
	RevokeCurrent  DeviceAccessAction = "revoke-current"
)

func New(store *admission.Store, authorityKeyDirectory string) (*Service, error) {
	if store == nil || authorityKeyDirectory == "" {
		return nil, errors.New("admission store and authority key directory are required")
	}
	return &Service{store: store, authorityKeyDirectory: authorityKeyDirectory}, nil
}

func (s *Service) ListWorkspaces(ctx context.Context) ([]admission.WorkspaceSummary, error) {
	return s.store.ListWorkspaces(ctx)
}

func (s *Service) ListDevices(
	ctx context.Context,
	workspaceID admission.WorkspaceID,
) ([]admission.DeviceSummary, error) {
	return s.store.ListDevices(ctx, workspaceID)
}

func (s *Service) IssuePairingCode(
	ctx context.Context,
	workspaceID admission.WorkspaceID,
	deviceType admission.DeviceType,
	deviceName string,
	now time.Time,
) (PairingCode, error) {
	code, err := s.store.IssuePairingCode(
		ctx, workspaceID, deviceType, deviceName, now, pairingCodeLifetime)
	if err != nil {
		return PairingCode{}, err
	}
	return PairingCode{Code: code, ExpiresAt: now.Add(pairingCodeLifetime)}, nil
}

func (s *Service) ApproveDevice(
	ctx context.Context,
	workspaceID admission.WorkspaceID,
	deviceReference string,
	now time.Time,
) (admission.ApprovedMembership, error) {
	device, err := s.device(ctx, workspaceID, deviceReference)
	if err != nil {
		return admission.ApprovedMembership{}, err
	}
	if device.MembershipState != "pending_approval" || device.Revoked {
		return admission.ApprovedMembership{}, ErrInvalidDeviceState
	}
	roles, err := productRoles(device.DeviceType)
	if err != nil {
		return admission.ApprovedMembership{}, err
	}
	privateKey, err := s.LoadAuthorityPrivateKey(ctx, workspaceID)
	if err != nil {
		return admission.ApprovedMembership{}, err
	}
	defer clear(privateKey)
	return s.store.ApprovePendingMembership(ctx, admission.ApprovePendingDevice{
		WorkspaceID: workspaceID, DeviceReference: deviceReference, Roles: roles,
		AuthorityPrivateKey: privateKey, Now: now,
	})
}

func (s *Service) ChangeDeviceAccess(
	ctx context.Context,
	workspaceID admission.WorkspaceID,
	deviceReference string,
	action DeviceAccessAction,
	now time.Time,
) (admission.RevokedDevice, error) {
	device, err := s.device(ctx, workspaceID, deviceReference)
	if err != nil {
		return admission.RevokedDevice{}, err
	}
	pending := device.MembershipState == "pending_proof" ||
		device.MembershipState == "pending_approval"
	approved := device.MembershipState == "approved"
	if device.Revoked ||
		(action == RejectPending && !pending) ||
		(action == RemoveApproved && !approved) ||
		(action != RejectPending && action != RemoveApproved && action != RevokeCurrent) {
		return admission.RevokedDevice{}, ErrInvalidDeviceState
	}
	var privateKey ed25519.PrivateKey
	if approved {
		privateKey, err = s.LoadAuthorityPrivateKey(ctx, workspaceID)
		if err != nil {
			return admission.RevokedDevice{}, err
		}
		defer clear(privateKey)
	}
	return s.store.RevokeDevice(ctx, admission.RevokeDeviceInput{
		WorkspaceID: workspaceID, DeviceReference: deviceReference,
		AuthorityPrivateKey: privateKey, Now: now,
	})
}

func (s *Service) LoadAuthorityPrivateKey(
	ctx context.Context,
	workspaceID admission.WorkspaceID,
) (ed25519.PrivateKey, error) {
	publicKey, err := s.store.WorkspaceAuthorityPublicKey(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	path := membership.AuthorityPrivateKeyPath(
		s.authorityKeyDirectory, membership.AuthorityKeyID(publicKey))
	return membership.LoadAuthorityPrivateKey(path, publicKey)
}

func (s *Service) device(
	ctx context.Context,
	workspaceID admission.WorkspaceID,
	deviceReference string,
) (admission.DeviceSummary, error) {
	devices, err := s.store.ListDevices(ctx, workspaceID)
	if err != nil {
		return admission.DeviceSummary{}, err
	}
	for _, device := range devices {
		if device.Reference == deviceReference {
			return device, nil
		}
	}
	return admission.DeviceSummary{}, admission.ErrDeviceNotFound
}

func productRoles(deviceType admission.DeviceType) ([]membershipv1.DeviceRole, error) {
	switch deviceType {
	case admission.DeviceAndroid:
		return []membershipv1.DeviceRole{
			membershipv1.DeviceRole_DEVICE_ROLE_SEND_NOTIFICATIONS,
		}, nil
	case admission.DeviceChrome:
		return []membershipv1.DeviceRole{
			membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS,
			membershipv1.DeviceRole_DEVICE_ROLE_INVOKE_NOTIFICATION_ACTIONS,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported device type %q", deviceType)
	}
}
