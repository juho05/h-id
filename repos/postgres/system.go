package postgres

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/postgres/db"
)

type systemRepository struct {
	db queryStore
}

func (d *DB) NewSystemRepository() repos.SystemRepository {
	return &systemRepository{
		db: d.db,
	}
}

func (r *systemRepository) GetJWTKeys(ctx context.Context) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	keys, err := r.db.GetJWTKeys(ctx)
	if err != nil {
		return nil, nil, repoErr("get JWT keys: %w", err)
	}
	privBlock, _ := pem.Decode(keys.Private)
	priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, repoErr("parse private key: %w", err)
	}
	pubBlock, _ := pem.Decode(keys.Public)
	pub, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, repoErr("parse public key: %w", err)
	}
	return priv, pub, nil
}

func (r *systemRepository) InsertJWTKeys(ctx context.Context, priv *rsa.PrivateKey, pub *rsa.PublicKey) error {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	})

	err := r.db.InsertJWTKeys(ctx, db.InsertJWTKeysParams{
		CreatedAt: time.Now().Unix(),
		Private:   keyPEM,
		Public:    pubPEM,
	})
	return repoErr("insert JWT keys: %w", err)
}
