package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	databasePath := os.Getenv("NM_DATABASE_PATH")
	if databasePath == "" {
		databasePath = "data/syncnotifications.db"
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		fatal("create data directory", err)
	}
	store, err := admission.Open(context.Background(), databasePath)
	if err != nil {
		fatal("open admission database", err)
	}
	defer store.Close()

	switch os.Args[1] {
	case "init-workspace":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		authority, err := membership.GenerateAuthority(authorityKeyDirectory(databasePath))
		if err != nil {
			fatal("generate workspace authority", err)
		}
		workspace, err := store.CreateWorkspace(
			context.Background(), authority.PublicKey, time.Now())
		if err != nil {
			if cleanupErr := os.Remove(authority.Path); cleanupErr != nil {
				fatal("initialize workspace",
					fmt.Errorf("%w; also failed to remove uncommitted authority key %q: %v",
						err, authority.Path, cleanupErr))
			}
			fatal("initialize workspace", err)
		}
		fmt.Printf("workspace_id=%s\n", base64.RawURLEncoding.EncodeToString(workspace[:]))
		fmt.Printf("authority_key_id=%s\n", authority.KeyID)
		fmt.Printf("authority_private_key_file=%s\n", authority.Path)
	case "issue-pairing-code":
		issuePairingCode(store, os.Args[2:])
	case "list-devices":
		listDevices(store, os.Args[2:])
	case "list-pending-devices":
		listPendingDevices(store, os.Args[2:])
	case "approve-device":
		approveDevice(store, databasePath, os.Args[2:])
	case "revoke-device":
		revokeDevice(store, os.Args[2:])
	case "issue-rotation-code":
		issueRotationCode(store, os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func issuePairingCode(store *admission.Store, args []string) {
	flags := flag.NewFlagSet("issue-pairing-code", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	deviceType := flags.String("type", "", "android or chrome")
	name := flags.String("name", "", "optional bound device name")
	ttl := flags.Duration("ttl", 10*time.Minute, "validity duration (maximum 24h)")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	code, err := store.IssuePairingCode(
		context.Background(), workspace, admission.DeviceType(*deviceType), *name, time.Now(), *ttl)
	if err != nil {
		fatal("issue pairing code", err)
	}
	// The raw single-use secret is printed exactly once and is never stored.
	fmt.Printf("pairing_code=%s\n", code)
	fmt.Printf("expires_in=%s\n", ttl.String())
}

func listDevices(store *admission.Store, args []string) {
	flags := flag.NewFlagSet("list-devices", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	devices, err := store.ListDevices(context.Background(), parseWorkspaceID(*workspaceText))
	if err != nil {
		fatal("list devices", err)
	}
	for _, device := range devices {
		status := "active"
		if device.Revoked {
			status = "revoked"
		}
		fmt.Printf("device_ref=%s type=%s status=%s name=%q\n",
			device.Reference, device.DeviceType, status, device.DeviceName)
	}
}

func listPendingDevices(store *admission.Store, args []string) {
	flags := flag.NewFlagSet("list-pending-devices", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	devices, err := store.ListPendingDevices(context.Background(), parseWorkspaceID(*workspaceText))
	if err != nil {
		fatal("list pending devices", err)
	}
	for _, device := range devices {
		fmt.Printf("device_ref=%s type=%s name=%q\n", device.Reference, device.DeviceType, device.DeviceName)
	}
}

func approveDevice(store *admission.Store, databasePath string, args []string) {
	flags := flag.NewFlagSet("approve-device", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	reference := flags.String("device-ref", "", "redacted device reference from list-pending-devices")
	rolesText := flags.String("roles", "", "comma-separated receive,send,invoke,manage roles")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	publicKey, err := store.WorkspaceAuthorityPublicKey(context.Background(), workspace)
	if err != nil {
		fatal("load workspace authority", err)
	}
	privateKeyPath := filepath.Join(authorityKeyDirectory(databasePath),
		"workspace-authority-"+membership.AuthorityKeyID(publicKey)+".pk8")
	privateKey, err := membership.LoadAuthorityPrivateKey(privateKeyPath, publicKey)
	if err != nil {
		fatal("load workspace authority", err)
	}
	defer clear(privateKey)
	approved, err := store.ApprovePendingMembership(context.Background(), admission.ApprovePendingDevice{
		WorkspaceID: workspace, DeviceReference: *reference, Roles: parseRoles(*rolesText),
		AuthorityPrivateKey: privateKey, Now: time.Now(),
	})
	if err != nil {
		fatal("approve device", err)
	}
	fmt.Printf("device_ref=%s result=approved roster_epoch=%d\n",
		approved.DeviceReference, approved.RosterEpoch)
}

func parseRoles(value string) []membershipv1.DeviceRole {
	roleValues := map[string]membershipv1.DeviceRole{
		"send":    membershipv1.DeviceRole_DEVICE_ROLE_SEND_NOTIFICATIONS,
		"receive": membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS,
		"invoke":  membershipv1.DeviceRole_DEVICE_ROLE_INVOKE_NOTIFICATION_ACTIONS,
		"manage":  membershipv1.DeviceRole_DEVICE_ROLE_MANAGE_DEVICES,
	}
	seen := make(map[membershipv1.DeviceRole]struct{})
	roles := make([]membershipv1.DeviceRole, 0)
	for _, item := range strings.Split(value, ",") {
		role, ok := roleValues[strings.TrimSpace(item)]
		if !ok {
			fatalMessage("--roles must be a non-empty comma-separated subset of send,receive,invoke,manage")
		}
		if _, duplicate := seen[role]; duplicate {
			fatalMessage("--roles must not contain duplicates")
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}
	if len(roles) == 0 {
		fatalMessage("--roles must be a non-empty comma-separated subset of send,receive,invoke,manage")
	}
	slices.Sort(roles)
	return roles
}

func authorityKeyDirectory(databasePath string) string {
	if value := os.Getenv("NM_AUTHORITY_KEY_DIR"); value != "" {
		return value
	}
	return filepath.Join(filepath.Dir(databasePath), "authority-keys")
}

func revokeDevice(store *admission.Store, args []string) {
	flags := flag.NewFlagSet("revoke-device", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	reference := flags.String("device-ref", "", "redacted device reference from list-devices")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	changed, err := store.RevokeDevice(
		context.Background(), parseWorkspaceID(*workspaceText), *reference, time.Now())
	if err != nil {
		fatal("revoke device", err)
	}
	result := "already-revoked"
	if changed {
		result = "revoked"
	}
	fmt.Printf("device_ref=%s result=%s\n", *reference, result)
}

func issueRotationCode(store *admission.Store, args []string) {
	flags := flag.NewFlagSet("issue-rotation-code", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	reference := flags.String("device-ref", "", "redacted device reference from list-devices")
	ttl := flags.Duration("ttl", 10*time.Minute, "validity duration (maximum 24h)")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	code, err := store.IssueCredentialRotationCode(
		context.Background(), parseWorkspaceID(*workspaceText), *reference, time.Now(), *ttl)
	if err != nil {
		fatal("issue credential rotation code", err)
	}
	// The raw device-bound secret is printed exactly once and is never stored.
	fmt.Printf("rotation_code=%s\n", code)
	fmt.Printf("device_ref=%s\n", *reference)
	fmt.Printf("expires_in=%s\n", ttl.String())
}

func parseWorkspaceID(value string) admission.WorkspaceID {
	workspaceBytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(workspaceBytes) != 16 || base64.RawURLEncoding.EncodeToString(workspaceBytes) != value {
		fatalMessage("--workspace must be a canonical 16-byte base64url ID")
	}
	var workspace admission.WorkspaceID
	copy(workspace[:], workspaceBytes)
	return workspace
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin init-workspace")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin issue-pairing-code --workspace <id> --type android|chrome [--name name] [--ttl 10m]")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin list-devices --workspace <id>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin list-pending-devices --workspace <id>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin approve-device --workspace <id> --device-ref <ref> --roles receive,invoke")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin revoke-device --workspace <id> --device-ref <ref>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin issue-rotation-code --workspace <id> --device-ref <ref> [--ttl 10m]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Set NM_DATABASE_PATH to use a non-default database.")
	fmt.Fprintln(os.Stderr, "Set NM_AUTHORITY_KEY_DIR to place new workspace authority private keys in a protected directory.")
}

func fatal(operation string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}

func fatalMessage(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
