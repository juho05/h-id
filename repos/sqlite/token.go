package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/juho05/h-id/repos"
)

type tokenRepository struct {
	db *sqlx.DB
}

func (d DB) NewTokenRepository() repos.TokenRepository {
	return &tokenRepository{
		db: d.db,
	}
}

func (t *tokenRepository) Create(ctx context.Context, category repos.TokenCategory, key string, valueHash []byte, lifetime time.Duration) (*repos.TokenModel, error) {
	token := &repos.TokenModel{
		CreatedAt: time.Now().Unix(),
		Category:  category,
		Key:       key,
		ValueHash: valueHash,
		Expires:   time.Now().Add(lifetime).Unix(),
	}
	_, err := t.db.Exec("REPLACE INTO tokens (created_at, category, token_key, value_hash, expires) VALUES (?, ?, ?, ?, ?)", token.CreatedAt, token.Category, token.Key, token.ValueHash, token.Expires)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	return token, nil
}

func (t *tokenRepository) Find(ctx context.Context, category repos.TokenCategory, key string) (*repos.TokenModel, error) {
	var token repos.TokenModel
	err := t.db.GetContext(ctx, &token, "SELECT * FROM tokens WHERE category = ? AND token_key = ? AND expires > ?", category, key, time.Now().Unix())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("find token: %w", err)
	}
	return &token, nil
}

func (t *tokenRepository) Delete(ctx context.Context, category repos.TokenCategory, key string) error {
	result, err := t.db.ExecContext(ctx, "DELETE FROM tokens WHERE category = ? AND token_key = ?", category, key)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("delete token: %w", repos.ErrNoRecord)
	}
	return nil
}
