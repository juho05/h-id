package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/Bananenpro/h-id/repos"
)

type oauthRepository struct {
	db *sqlx.DB
}

func (d *DB) NewOAuthRepository() repos.OAuthRepository {
	return &oauthRepository{
		db: d.db,
	}
}

func (a *oauthRepository) Create(ctx context.Context, clientID, userID string, category repos.OAuthTokenCategory, tokenHash []byte, redirectURI string, scopes []string, data []byte, lifetime time.Duration) (*repos.OAuthTokenModel, error) {
	token := &repos.OAuthTokenModel{
		CreatedAt:   time.Now().Unix(),
		Category:    category,
		TokenHash:   tokenHash,
		RedirectURI: redirectURI,
		ClientID:    clientID,
		UserID:      userID,
		Scopes:      scopes,
		Data:        data,
		Expires:     time.Now().Add(lifetime).Unix(),
		Used:        false,
	}
	_, err := a.db.ExecContext(ctx, "INSERT INTO oauth (created_at, category, token_hash, redirect_uri, client_id, user_id, scopes, data, expires, used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", token.CreatedAt, token.Category, token.TokenHash, token.RedirectURI, token.ClientID, token.UserID, token.Scopes, token.Data, token.Expires, token.Used)
	if err != nil {
		return nil, fmt.Errorf("create OAuth token: %w", err)
	}
	return token, nil
}

func (a *oauthRepository) Find(ctx context.Context, category repos.OAuthTokenCategory, tokenHash []byte) (*repos.OAuthTokenModel, error) {
	var token repos.OAuthTokenModel
	err := a.db.GetContext(ctx, &token, "SELECT * FROM oauth WHERE category = ? AND token_hash = ? AND expires > ?", category, tokenHash, time.Now().Unix())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("find OAuth token: %w", err)
	}
	return &token, nil
}

func (a *oauthRepository) Use(ctx context.Context, clientID string, category repos.OAuthTokenCategory, tokenHash []byte) error {
	result, err := a.db.ExecContext(ctx, "UPDATE oauth SET used = ? WHERE client_id = ? AND category = ? AND token_hash = ?", true, clientID, category, tokenHash)
	if err != nil {
		return fmt.Errorf("use OAuth token: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("use OAuth token: %w", repos.ErrNoRecord)
	}
	return nil
}

func (a *oauthRepository) Delete(ctx context.Context, clientID string, category repos.OAuthTokenCategory, tokenHash []byte) error {
	result, err := a.db.ExecContext(ctx, "DELETE FROM oauth WHERE client_id = ? AND category = ? AND tokenHash = ?", clientID, category, tokenHash)
	if err != nil {
		return fmt.Errorf("delete OAuth token: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("delete OAuth token: %w", repos.ErrNoRecord)
	}
	return nil
}

func (a *oauthRepository) DeleteByUser(ctx context.Context, clientID, userID string) error {
	_, err := a.db.ExecContext(ctx, "DELETE FROM oauth WHERE client_id = ? AND user_id = ?", clientID, userID)
	if err != nil {
		return fmt.Errorf("delete OAuth token: %w", err)
	}
	return nil
}
