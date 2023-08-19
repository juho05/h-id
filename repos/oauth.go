package repos

import (
	"context"
	"net/url"
	"time"

	"github.com/oklog/ulid/v2"
)

type OAuthTokenCategory string

var (
	OAuthTokenCode    OAuthTokenCategory = "code"
	OAuthTokenAccess  OAuthTokenCategory = "access"
	OAuthTokenRefresh OAuthTokenCategory = "refresh"
)

type OAuthTokenModel struct {
	CreatedAt   time.Time
	Category    OAuthTokenCategory
	TokenHash   []byte
	RedirectURI *url.URL
	ClientID    ulid.ULID
	UserID      ulid.ULID
	Scopes      []string
	Data        []byte
	Expires     time.Time
	Used        bool
}

type PermissionsModel struct {
	CreatedAt time.Time
	ClientID  ulid.ULID
	UserID    ulid.ULID
	Scopes    []string
}

type OAuthRepository interface {
	Create(ctx context.Context, clientID, userID ulid.ULID, category OAuthTokenCategory, tokenHash []byte, redirectURI *url.URL, scopes []string, data []byte, lifetime time.Duration) (*OAuthTokenModel, error)
	Find(ctx context.Context, category OAuthTokenCategory, tokenHash []byte) (*OAuthTokenModel, error)
	Use(ctx context.Context, clientID ulid.ULID, category OAuthTokenCategory, tokenHash []byte) error
	Delete(ctx context.Context, clientID ulid.ULID, category OAuthTokenCategory, tokenHash []byte) error
	DeleteByUser(ctx context.Context, clientID, userID ulid.ULID) error

	SetPermissions(ctx context.Context, clientID, userID ulid.ULID, scopes []string) (*PermissionsModel, error)
	FindPermissions(ctx context.Context, clientID, userID ulid.ULID) (*PermissionsModel, error)
	RevokePermissions(ctx context.Context, clientID, userID ulid.ULID) error
}
