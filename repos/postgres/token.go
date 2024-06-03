package postgres

import (
	"context"
	"time"

	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/postgres/db"
)

type tokenRepository struct {
	db queryStore
}

func (d DB) NewTokenRepository() repos.TokenRepository {
	return &tokenRepository{
		db: d.db,
	}
}

func repoToken(token db.Token) *repos.TokenModel {
	return &repos.TokenModel{
		CreatedAt: time.Unix(token.CreatedAt, 0),
		Category:  repos.TokenCategory(token.Category),
		Key:       token.TokenKey,
		ValueHash: token.ValueHash,
		Expires:   time.Unix(token.Expires, 0),
	}
}

func (t *tokenRepository) Create(ctx context.Context, category repos.TokenCategory, key string, valueHash []byte, lifetime time.Duration) (*repos.TokenModel, error) {
	token, err := t.db.CreateToken(ctx, db.CreateTokenParams{
		CreatedAt: time.Now().Unix(),
		Category:  string(category),
		TokenKey:  key,
		ValueHash: valueHash,
		Expires:   time.Now().Add(lifetime).Unix(),
	})
	return repoToken(token), repoErr("create token: %w", err)
}

func (t *tokenRepository) Find(ctx context.Context, category repos.TokenCategory, key string) (*repos.TokenModel, error) {
	token, err := t.db.FindToken(ctx, db.FindTokenParams{
		Category: string(category),
		TokenKey: key,
		Now:      time.Now().Unix(),
	})
	if err != nil {
		return nil, repoErr("find token: %w", err)
	}
	return repoToken(token), nil
}

func (t *tokenRepository) FindByValue(ctx context.Context, category repos.TokenCategory, valueHash []byte) (*repos.TokenModel, error) {
	token, err := t.db.FindTokenByValue(ctx, db.FindTokenByValueParams{
		Category:  string(category),
		ValueHash: valueHash,
		Now:       time.Now().Unix(),
	})
	if err != nil {
		return nil, repoErr("find token by value hash: %w", err)
	}
	return repoToken(token), nil
}

func (t *tokenRepository) Delete(ctx context.Context, category repos.TokenCategory, key string) error {
	result, err := t.db.DeleteToken(ctx, db.DeleteTokenParams{
		Category: string(category),
		TokenKey: key,
		Now:      time.Now().Unix(),
	})
	return repoErrResult("delete token: %w", result, err)
}
