package sqlite

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/sqlite/db"
)

type gatewayTokenRepository struct {
	db *db.Queries
}

func (d DB) NewGatewayTokenRepository() repos.GatewayTokenRepository {
	return &gatewayTokenRepository{
		db: d.db,
	}
}

func repoGatewayToken(token db.GatewayToken) (*repos.GatewayTokenModel, error) {
	userID, err := ulid.Parse(token.UserID)
	if err != nil {
		return nil, err
	}
	return &repos.GatewayTokenModel{
		CreatedAt: time.Unix(token.CreatedAt, 0),
		UserID:    userID,
		TokenHash: token.TokenHash,
		Expires:   time.Unix(token.Expires, 0),
	}, nil
}

func (t *gatewayTokenRepository) Create(ctx context.Context, userID ulid.ULID, tokenHash []byte, lifetime time.Duration) error {
	err := t.db.CreateGatewayToken(ctx, db.CreateGatewayTokenParams{
		CreatedAt: time.Now().Unix(),
		UserID:    userID.String(),
		TokenHash: tokenHash,
		Expires:   time.Now().Add(lifetime).Unix(),
	})
	return repoErr("create gateway token: %w", err)
}

func (t *gatewayTokenRepository) FindByHash(ctx context.Context, tokenHash []byte) (*repos.GatewayTokenModel, error) {
	token, err := t.db.FindGatewayToken(ctx, db.FindGatewayTokenParams{
		TokenHash: tokenHash,
		Now:       time.Now().Unix(),
	})
	if err != nil {
		return nil, repoErr("find gateway token by hash: %w", err)
	}
	return repoGatewayToken(token)
}

func (t *gatewayTokenRepository) Delete(ctx context.Context, tokenHash []byte) error {
	result, err := t.db.DeleteGatewayToken(ctx, db.DeleteGatewayTokenParams{
		TokenHash: tokenHash,
		Now:       time.Now().Unix(),
	})
	return repoErrResult("delete gateway token: %w", result, err)
}

func (t *gatewayTokenRepository) DeleteByUser(ctx context.Context, userID ulid.ULID) error {
	result, err := t.db.DeleteGatewayTokensByUser(ctx, db.DeleteGatewayTokensByUserParams{
		UserID: userID.String(),
		Now:    time.Now().Unix(),
	})
	return repoErrResult("delete gateway tokens by user: %w", result, err)
}
