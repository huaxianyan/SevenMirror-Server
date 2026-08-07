package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
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
		workspace, err := store.CreateWorkspace(context.Background(), time.Now())
		if err != nil {
			fatal("initialize workspace", err)
		}
		fmt.Printf("workspace_id=%s\n", base64.RawURLEncoding.EncodeToString(workspace[:]))
	case "issue-pairing-code":
		issuePairingCode(store, os.Args[2:])
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
	workspaceBytes, err := base64.RawURLEncoding.DecodeString(*workspaceText)
	if err != nil || len(workspaceBytes) != 16 {
		fatalMessage("--workspace must be a 16-byte base64url ID")
	}
	var workspace admission.WorkspaceID
	copy(workspace[:], workspaceBytes)
	code, err := store.IssuePairingCode(
		context.Background(), workspace, admission.DeviceType(*deviceType), *name, time.Now(), *ttl)
	if err != nil {
		fatal("issue pairing code", err)
	}
	// The raw single-use secret is printed exactly once and is never stored.
	fmt.Printf("pairing_code=%s\n", code)
	fmt.Printf("expires_in=%s\n", ttl.String())
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin init-workspace")
	fmt.Fprintln(os.Stderr, "  notification-mirroring-admin issue-pairing-code --workspace <id> --type android|chrome [--name name] [--ttl 10m]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Set NM_DATABASE_PATH to use a non-default database.")
}

func fatal(operation string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}

func fatalMessage(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
