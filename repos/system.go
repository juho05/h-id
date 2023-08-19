package repos

import (
	"context"
	"crypto/rsa"
)

type SystemRepository interface {
	GetJWTKeys(ctx context.Context) (*rsa.PrivateKey, *rsa.PublicKey, error)
	InsertJWTKeys(ctx context.Context, priv *rsa.PrivateKey, pub *rsa.PublicKey) error
}
