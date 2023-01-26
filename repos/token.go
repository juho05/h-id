package repos

import (
	"context"
	"time"
)

type TokenCategory string

var TokenConfirmEmail TokenCategory = "confirm-email"

type TokenModel struct {
	CreatedAt int64         `db:"created_at"`
	Category  TokenCategory `db:"category"`
	Key       string        `db:"token_key"`
	ValueHash []byte        `db:"value_hash"`
	Expires   int64         `db:"expires"`
}

type TokenRepository interface {
	Create(ctx context.Context, category TokenCategory, key string, valueHash []byte, lifetime time.Duration) (*TokenModel, error)
	Find(ctx context.Context, category TokenCategory, key string) (*TokenModel, error)
	Delete(ctx context.Context, category TokenCategory, key string) error
}
