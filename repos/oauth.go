package repos

import (
	"context"
	"time"
)

type OAuthTokenCategory string

var (
	OAuthTokenCode    OAuthTokenCategory = "code"
	OAuthTokenAccess  OAuthTokenCategory = "access"
	OAuthTokenRefresh OAuthTokenCategory = "refresh"
)

type OAuthTokenModel struct {
	CreatedAt   int64              `db:"created_at"`
	Category    OAuthTokenCategory `db:"category"`
	TokenHash   []byte             `db:"token_hash"`
	RedirectURI string             `db:"redirect_uri"`
	ClientID    string             `db:"client_id"`
	UserID      string             `db:"user_id"`
	Scopes      StringSlice        `db:"scopes"`
	Data        []byte             `db:"data"`
	Expires     int64              `db:"expires"`
	Used        bool               `db:"used"`
}

type PermissionsModel struct {
	CreatedAt int64       `db:"created_at"`
	ClientID  string      `db:"client_id"`
	UserID    string      `db:"user_id"`
	Scopes    StringSlice `db:"scopes"`
}

type OAuthRepository interface {
	Create(ctx context.Context, clientID, userID string, category OAuthTokenCategory, tokenHash []byte, redirectURI string, scopes []string, data []byte, lifetime time.Duration) (*OAuthTokenModel, error)
	Find(ctx context.Context, category OAuthTokenCategory, tokenHash []byte) (*OAuthTokenModel, error)
	Use(ctx context.Context, clientID string, category OAuthTokenCategory, tokenHash []byte) error
	Delete(ctx context.Context, clientID string, category OAuthTokenCategory, tokenHash []byte) error
	DeleteByUser(ctx context.Context, clientID, userID string) error

	SetPermissions(ctx context.Context, clientID, userID string, scopes []string) (*PermissionsModel, error)
	FindAllPermissions(ctx context.Context, userID string) ([]*PermissionsModel, error)
	FindPermissions(ctx context.Context, clientID, userID string) (*PermissionsModel, error)
	RevokePermissions(ctx context.Context, clientID, userID string) error
}
