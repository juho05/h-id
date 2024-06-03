package postgres

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/postgres/db"
)

type oauthRepository struct {
	db queryStore
}

func (d *DB) NewOAuthRepository() repos.OAuthRepository {
	return &oauthRepository{
		db: d.db,
	}
}

func repoOAuthToken(token db.Oauth) (*repos.OAuthTokenModel, error) {
	redirectURI, err := url.Parse(token.RedirectUri)
	if err != nil {
		return nil, err
	}
	clientID, err := ulid.Parse(token.ClientID)
	if err != nil {
		return nil, err
	}
	userID, err := ulid.Parse(token.UserID)
	if err != nil {
		return nil, err
	}
	return &repos.OAuthTokenModel{
		CreatedAt:   time.Unix(token.CreatedAt, 0),
		Category:    repos.OAuthTokenCategory(token.Category),
		TokenHash:   token.TokenHash,
		RedirectURI: redirectURI,
		ClientID:    clientID,
		UserID:      userID,
		Scopes:      strings.Split(token.Scopes, ","),
		Data:        token.Data,
		Expires:     time.Unix(token.Expires, 0),
		Used:        token.Used,
	}, nil
}

func repoOAuthPermissions(perms db.Permission) (*repos.PermissionsModel, error) {
	userID, err := ulid.Parse(perms.UserID)
	if err != nil {
		return nil, err
	}
	clientID, err := ulid.Parse(perms.ClientID)
	if err != nil {
		return nil, err
	}
	return &repos.PermissionsModel{
		CreatedAt: time.Unix(perms.CreatedAt, 0),
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    strings.Split(perms.Scopes, ","),
	}, nil
}

func (a *oauthRepository) Create(ctx context.Context, clientID, userID ulid.ULID, category repos.OAuthTokenCategory, tokenHash []byte, redirectURI *url.URL, scopes []string, data []byte, lifetime time.Duration) (*repos.OAuthTokenModel, error) {
	var redirectURIStr string
	if redirectURI != nil {
		redirectURIStr = redirectURI.String()
	}
	token, err := a.db.CreateOAuthToken(ctx, db.CreateOAuthTokenParams{
		CreatedAt:   time.Now().Unix(),
		Category:    string(category),
		TokenHash:   tokenHash,
		RedirectUri: redirectURIStr,
		Scopes:      strings.Join(scopes, ","),
		Data:        data,
		ClientID:    clientID.String(),
		UserID:      userID.String(),
		Expires:     time.Now().Add(lifetime).Unix(),
		Used:        false,
	})
	if err != nil {
		return nil, repoErr("create oauth token: %w", err)
	}
	return repoOAuthToken(token)
}

func (a *oauthRepository) Find(ctx context.Context, category repos.OAuthTokenCategory, tokenHash []byte) (*repos.OAuthTokenModel, error) {
	token, err := a.db.FindOAuthToken(ctx, db.FindOAuthTokenParams{
		Category:  string(category),
		TokenHash: tokenHash,
		Now:       time.Now().Unix(),
	})
	if err != nil {
		return nil, repoErr("find oauth token: %w", err)
	}
	return repoOAuthToken(token)
}

func (a *oauthRepository) Use(ctx context.Context, clientID ulid.ULID, category repos.OAuthTokenCategory, tokenHash []byte) error {
	result, err := a.db.UseOAuthToken(ctx, db.UseOAuthTokenParams{
		ClientID:  clientID.String(),
		Category:  string(category),
		TokenHash: tokenHash,
	})
	return repoErrResult("use oauth token: %w", result, err)
}

func (a *oauthRepository) Delete(ctx context.Context, clientID ulid.ULID, category repos.OAuthTokenCategory, tokenHash []byte) error {
	result, err := a.db.DeleteOAuthToken(ctx, db.DeleteOAuthTokenParams{
		ClientID:  clientID.String(),
		Category:  string(category),
		TokenHash: tokenHash,
	})
	return repoErrResult("delete oauth token: %w", result, err)
}

func (a *oauthRepository) DeleteByUser(ctx context.Context, clientID, userID ulid.ULID) error {
	err := a.db.DeleteOAuthTokenByUser(ctx, db.DeleteOAuthTokenByUserParams{
		ClientID: clientID.String(),
		UserID:   userID.String(),
		Now:      time.Now().Unix(),
	})
	return repoErr("delete oauth token by user: %w", err)
}

func (a *oauthRepository) SetPermissions(ctx context.Context, clientID, userID ulid.ULID, scopes []string) (*repos.PermissionsModel, error) {
	permissions, err := a.db.SetOAuthPermissions(ctx, db.SetOAuthPermissionsParams{
		CreatedAt: time.Now().Unix(),
		ClientID:  clientID.String(),
		UserID:    userID.String(),
		Scopes:    strings.Join(scopes, ","),
	})
	if err != nil {
		return nil, repoErr("set oauth permissions: %w", err)
	}
	return repoOAuthPermissions(permissions)
}

func (a *oauthRepository) FindPermissions(ctx context.Context, clientID, userID ulid.ULID) (*repos.PermissionsModel, error) {
	perms, err := a.db.FindOAuthPermissions(ctx, db.FindOAuthPermissionsParams{
		ClientID: clientID.String(),
		UserID:   userID.String(),
	})
	if err != nil {
		return nil, repoErr("find oauth permissions: %w", err)
	}
	return repoOAuthPermissions(perms)
}

func (a *oauthRepository) RevokePermissions(ctx context.Context, clientID, userID ulid.ULID) error {
	result, err := a.db.RevokeOAuthPermissions(ctx, db.RevokeOAuthPermissionsParams{
		ClientID: clientID.String(),
		UserID:   userID.String(),
	})
	return repoErrResult("revoke oauth permissions: %w", result, err)
}
