package repos

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/oklog/ulid/v2"
	"github.com/pquerna/otp"
)

type UserModel struct {
	BaseModel
	Name           string
	Email          string
	EmailConfirmed bool
	OTPActive      bool
	OTPKey         *otp.Key
	PasswordHash   []byte
}

type Passkey struct {
	BaseModel
	Name       string
	UserID     ulid.ULID
	Credential webauthn.Credential
}

type UserRepository interface {
	Find(ctx context.Context, id ulid.ULID) (*UserModel, error)
	FindByEmail(ctx context.Context, email string) (*UserModel, error)
	FindByChangeEmailToken(ctx context.Context, tokenHash []byte) (*UserModel, error)
	GetPasswordHash(ctx context.Context, userID ulid.ULID) ([]byte, error)
	GetOTP(ctx context.Context, userID ulid.ULID) (active bool, key *otp.Key, err error)
	Create(ctx context.Context, name, email string, passwordHash []byte) (*UserModel, error)
	UpdateName(ctx context.Context, id ulid.ULID, name string) error
	UpdatePassword(ctx context.Context, id ulid.ULID, passwordHash []byte) error
	UpdateEmailConfirmed(ctx context.Context, id ulid.ULID, confirmed bool) error
	UpdateOTP(ctx context.Context, id ulid.ULID, active bool, otpKey *otp.Key) error
	CreateChangeEmailRequest(ctx context.Context, userID ulid.ULID, newEmail string, tokenHash []byte, lifetime time.Duration) error
	UpdateEmail(ctx context.Context, changeTokenHash []byte) (string, error)
	CreateRecoveryCodes(ctx context.Context, userID ulid.ULID, codeHashes [][]byte) error
	CountRecoveryCodes(ctx context.Context, userID ulid.ULID) (int, error)
	DeleteRecoveryCode(ctx context.Context, userID ulid.ULID, codeHash []byte) error
	DeleteRecoveryCodes(ctx context.Context, userID ulid.ULID) error
	CreatePasskey(ctx context.Context, userID ulid.ULID, name string, credential webauthn.Credential) error
	GetPasskeys(ctx context.Context, userID ulid.ULID) ([]*Passkey, error)
	GetPasskey(ctx context.Context, userID, id ulid.ULID) (*Passkey, error)
	UpdatePasskeyCredential(ctx context.Context, userID ulid.ULID, credential webauthn.Credential) error
	UpdatePasskey(ctx context.Context, userID, id ulid.ULID, name string) error
	DeletePasskey(ctx context.Context, userID, id ulid.ULID) error
	Delete(ctx context.Context, id ulid.ULID) error
}
