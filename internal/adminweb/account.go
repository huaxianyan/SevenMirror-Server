package adminweb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

const (
	// DefaultAdministratorName is the account a registry without a stored credential
	// answers to. Its password is published in docs/admin-web.md, which is exactly
	// why the console serves nothing but the credential setup until an administrator
	// replaces both: the default is a starting point, never a usable state.
	DefaultAdministratorName = "admin"

	defaultAdministratorPassword = "sevenmirror"

	minPasswordBytes    = 12
	maxPasswordBytes    = 256
	maxAccountNameBytes = 64
)

// AccountStore is the console account as the registry persists it. A registry
// without a row reports found as false rather than an error, which is the state a
// fresh deployment starts in.
type AccountStore interface {
	LoadAdministrator(context.Context) (admission.AdministratorCredential, bool, error)
	SaveAdministrator(context.Context, admission.AdministratorCredential) error
}

// account is the credential state logins are checked against. initialized stays
// false while the built-in default is in force, and the second factor is absent
// until setup stored a secret.
type account struct {
	name         string
	hash         passwordHash
	secret       []byte
	secondFactor *totpVerifier
	updatedAt    time.Time
	initialized  bool
}

func defaultAccount() account { return account{name: DefaultAdministratorName} }

// accountFromCredential turns a stored row into runtime state. A row the console
// cannot parse is a hard error: silently falling back to the default account would
// quietly downgrade a deployed console to its default password.
func accountFromCredential(credential admission.AdministratorCredential) (account, error) {
	name := strings.TrimSpace(credential.Name)
	if err := validateAccountName(name); err != nil {
		return account{}, fmt.Errorf("stored administrator name: %w", err)
	}
	hash, err := parsePasswordHash(credential.PasswordHash)
	if err != nil {
		return account{}, fmt.Errorf("stored administrator password hash: %w", err)
	}
	secret, err := parseTOTPSecret(credential.TOTPSecret)
	if err != nil {
		return account{}, fmt.Errorf("stored administrator TOTP secret: %w", err)
	}
	return account{
		name: name, hash: hash, secret: secret, secondFactor: newTOTPVerifier(secret),
		updatedAt: credential.UpdatedAt, initialized: true,
	}, nil
}

func (a account) nameMatches(candidate string) bool {
	if !a.initialized {
		return constantTimeEquals(candidate, DefaultAdministratorName)
	}
	return constantTimeEquals(candidate, a.name)
}

// passwordMatches reports whether the presented password verifies. The default
// account compares against the built-in password; whenever the name differs the
// scrypt verifier still runs, so a wrong name does not answer faster than a wrong
// password.
func (a account) passwordMatches(password string) bool {
	if !a.initialized {
		return constantTimeEquals(password, defaultAdministratorPassword)
	}
	return a.hash.matches(password)
}

// validateAccountName returns a message meant for the setup form.
func validateAccountName(name string) error {
	if name == "" || len(name) > maxAccountNameBytes || !printableName(name) {
		return fmt.Errorf("用户名须为 1 到 %d 个字节，不含空格或控制字符。", maxAccountNameBytes)
	}
	return nil
}

// validateNewPassword returns a message meant for the setup form. The default
// password is refused outright: the whole point of the first sign-in is to retire
// a value that is published in the manual.
func validateNewPassword(password string) error {
	if len(password) < minPasswordBytes || len(password) > maxPasswordBytes {
		return fmt.Errorf("新密码须为 %d 到 %d 个字节。", minPasswordBytes, maxPasswordBytes)
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("新密码不能只由空格组成。")
	}
	if hasControlCharacter(password) {
		return errors.New("新密码不能包含控制字符。")
	}
	if constantTimeEquals(password, defaultAdministratorPassword) {
		return errors.New("新密码不能沿用初始密码。")
	}
	return nil
}

func printableName(name string) bool {
	for index := 0; index < len(name); index++ {
		if name[index] <= ' ' || name[index] == 0x7f {
			return false
		}
	}
	return true
}

func hasControlCharacter(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < ' ' || value[index] == 0x7f {
			return true
		}
	}
	return false
}
