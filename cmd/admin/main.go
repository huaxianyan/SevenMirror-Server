package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/adminservice"
	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	"github.com/huaxianyan/SyncNotifications-Server/internal/workspacebackup"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if os.Args[1] == "verify-workspace-backup" {
		verifyWorkspaceBackup(os.Args[2:])
		return
	}
	if os.Args[1] == "restore-workspace-backup" {
		restoreWorkspaceBackup(os.Args[2:])
		return
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
	management, err := adminservice.New(store, authorityKeyDirectory(databasePath))
	if err != nil {
		fatal("configure administration", err)
	}

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
	case "backup-workspace":
		backupWorkspace(store, databasePath, os.Args[2:])
	case "prepare-authority-rotation":
		prepareAuthorityRotation(databasePath, os.Args[2:])
	case "rotate-authority":
		rotateAuthority(store, management, os.Args[2:])
	case "issue-pairing-code":
		issuePairingCode(management, os.Args[2:])
	case "list-devices":
		listDevices(store, os.Args[2:])
	case "list-pending-devices":
		listPendingDevices(store, os.Args[2:])
	case "approve-device":
		approveDevice(management, os.Args[2:])
	case "revoke-device":
		revokeDevice(management, os.Args[2:])
	case "issue-rotation-code":
		issueRotationCode(store, os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func backupWorkspace(store *admission.Store, databasePath string, args []string) {
	flags := flag.NewFlagSet("backup-workspace", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	outputDirectory := flags.String("output", "", "new protected workspace backup directory")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	backup, err := workspacebackup.Create(
		context.Background(), store, *outputDirectory, workspace,
		authorityKeyDirectory(databasePath))
	if err != nil {
		fatal("back up workspace", err)
	}
	fmt.Printf("workspace_id=%s\n", base64.RawURLEncoding.EncodeToString(workspace[:]))
	fmt.Printf("authority_key_id=%s\n", backup.AuthorityKeyID)
	fmt.Printf("workspace_backup_directory=%s\n", backup.Directory)
}

func verifyWorkspaceBackup(args []string) {
	flags := flag.NewFlagSet("verify-workspace-backup", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	backupDirectory := flags.String("backup", "", "workspace backup directory")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	verified, err := workspacebackup.Verify(context.Background(), *backupDirectory, workspace)
	if err != nil {
		fatal("verify workspace backup", err)
	}
	fmt.Printf("workspace_id=%s\n", base64.RawURLEncoding.EncodeToString(workspace[:]))
	fmt.Printf("authority_key_id=%s\n", verified.AuthorityKeyID)
	fmt.Println("result=verified")
}

func restoreWorkspaceBackup(args []string) {
	flags := flag.NewFlagSet("restore-workspace-backup", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	backupDirectory := flags.String("backup", "", "workspace backup directory")
	databasePath := flags.String("database", "", "new restored registry path")
	authorityDirectory := flags.String(
		"authority-key-directory", "", "restored authority key directory")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	restored, err := workspacebackup.RestoreTo(
		context.Background(), *backupDirectory, workspace,
		*databasePath, *authorityDirectory)
	if err != nil {
		fatal("restore workspace backup", err)
	}
	result := "restored"
	if restored.AuthorityExisted {
		result = "registry-restored-authority-already-present"
	}
	fmt.Printf("workspace_id=%s\n", base64.RawURLEncoding.EncodeToString(workspace[:]))
	fmt.Printf("registry_file=%s\n", restored.RegistryPath)
	fmt.Printf("authority_private_key_file=%s\n", restored.AuthorityKeyPath)
	fmt.Printf("result=%s\n", result)
}

func prepareAuthorityRotation(databasePath string, args []string) {
	flags := flag.NewFlagSet("prepare-authority-rotation", flag.ExitOnError)
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	generated, err := membership.GenerateAuthority(authorityKeyDirectory(databasePath))
	if err != nil {
		fatal("prepare workspace authority rotation", err)
	}
	fmt.Printf("new_authority_key_id=%s\n", generated.KeyID)
	fmt.Printf("new_authority_private_key_file=%s\n", generated.Path)
	fmt.Println("result=prepared")
}

func rotateAuthority(
	store *admission.Store,
	management *adminservice.Service,
	args []string,
) {
	flags := flag.NewFlagSet("rotate-authority", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	newKeyFile := flags.String("new-key-file", "", "prepared protected Ed25519 PKCS#8 key file")
	flags.Parse(args)
	if flags.NArg() != 0 || strings.TrimSpace(*newKeyFile) == "" {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	newPublicKey, newPrivateKey, err := membership.LoadAuthorityKey(*newKeyFile)
	if err != nil {
		fatal("load prepared workspace authority", err)
	}
	defer clear(newPrivateKey)
	if completed, ok, err := store.CompletedWorkspaceAuthorityRotation(context.Background(), workspace, newPublicKey); err != nil {
		fatal("recover workspace authority rotation", err)
	} else if ok {
		printAuthorityRotation(workspace, newPublicKey, completed, "already-rotated")
		return
	}
	previousPrivateKey, err := management.LoadAuthorityPrivateKey(
		context.Background(), workspace)
	if err != nil {
		fatal("load current workspace authority", err)
	}
	defer clear(previousPrivateKey)
	rotated, err := store.RotateWorkspaceAuthority(context.Background(), admission.RotateWorkspaceAuthorityInput{
		WorkspaceID: workspace, PreviousAuthorityPrivateKey: previousPrivateKey,
		NewAuthorityPrivateKey: newPrivateKey, Now: time.Now(),
	})
	if err != nil {
		fatal("rotate workspace authority", err)
	}
	printAuthorityRotation(workspace, newPublicKey, rotated, "rotated")
}

func printAuthorityRotation(workspace admission.WorkspaceID, publicKey membership.AuthorityPublicKey, rotated admission.RotatedWorkspaceAuthority, result string) {
	fmt.Printf("workspace_id=%s\n", base64.RawURLEncoding.EncodeToString(workspace[:]))
	fmt.Printf("authority_key_id=%s\n", membership.AuthorityKeyID(publicKey))
	fmt.Printf("authority_epoch=%d\n", rotated.AuthorityEpoch)
	fmt.Printf("activation_roster_epoch=%d\n", rotated.RosterEpoch)
	fmt.Printf("transition_digest=%s\n", base64.RawURLEncoding.EncodeToString(rotated.TransitionDigest[:]))
	fmt.Printf("result=%s\n", result)
}

func issuePairingCode(management *adminservice.Service, args []string) {
	flags := flag.NewFlagSet("issue-pairing-code", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	deviceType := flags.String("type", "", "android or chrome")
	name := flags.String("name", "", "optional bound device name")
	ttl := flags.Duration("ttl", adminservice.DefaultPairingCodeLifetime,
		"validity duration (maximum 24h)")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	issued, err := management.IssuePairingCode(
		context.Background(), workspace, admission.DeviceType(*deviceType), *name, time.Now(), *ttl)
	if err != nil {
		fatal("issue pairing code", err)
	}
	// The raw single-use secret is printed exactly once and is never stored.
	fmt.Printf("pairing_code=%s\n", issued.Code)
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

func approveDevice(management *adminservice.Service, args []string) {
	flags := flag.NewFlagSet("approve-device", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	reference := flags.String("device-ref", "", "redacted device reference from list-pending-devices")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	approved, err := management.ApproveDevice(
		context.Background(), parseWorkspaceID(*workspaceText), *reference, time.Now())
	if err != nil {
		fatal("approve device", err)
	}
	fmt.Printf("device_ref=%s result=approved roster_epoch=%d\n",
		approved.DeviceReference, approved.RosterEpoch)
}

func authorityKeyDirectory(databasePath string) string {
	if value := os.Getenv("NM_AUTHORITY_KEY_DIR"); value != "" {
		return value
	}
	return filepath.Join(filepath.Dir(databasePath), "authority-keys")
}

func revokeDevice(management *adminservice.Service, args []string) {
	flags := flag.NewFlagSet("revoke-device", flag.ExitOnError)
	workspaceText := flags.String("workspace", "", "base64url workspace ID")
	reference := flags.String("device-ref", "", "redacted device reference from list-devices")
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	workspace := parseWorkspaceID(*workspaceText)
	revoked, err := management.ChangeDeviceAccess(
		context.Background(), workspace, *reference,
		adminservice.RevokeCurrent, time.Now())
	if err != nil {
		fatal("revoke device", err)
	}
	result := "already-revoked"
	if revoked.Changed {
		result = "revoked"
	}
	if revoked.RosterEpoch > 0 {
		fmt.Printf("device_ref=%s result=%s roster_epoch=%d\n",
			*reference, result, revoked.RosterEpoch)
		return
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
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin backup-workspace --workspace <id> --output <new-directory>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin verify-workspace-backup --workspace <id> --backup <directory>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin restore-workspace-backup --workspace <id> --backup <directory> --database <new-file> --authority-key-directory <directory>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin prepare-authority-rotation")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin rotate-authority --workspace <id> --new-key-file <path>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin issue-pairing-code --workspace <id> --type android|chrome [--name name] [--ttl 10m]")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin list-devices --workspace <id>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin list-pending-devices --workspace <id>")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin approve-device --workspace <id> --device-ref <ref>")
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
