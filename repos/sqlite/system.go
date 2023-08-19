package sqlite

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/juho05/h-id/repos"
)

type rsaKeyModel struct {
	Name      string `db:"name"`
	CreatedAt int64  `db:"created_at"`
	Private   []byte `db:"private"`
	Public    []byte `db:"public"`
}

type systemRepository struct {
	db *sqlx.DB
}

func (d *DB) NewSystemRepository() repos.SystemRepository {
	return &systemRepository{
		db: d.db,
	}
}

func (r *systemRepository) GetJWTKeys(ctx context.Context) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var model rsaKeyModel
	err := r.db.GetContext(ctx, &model, "SELECT * FROM rsa_keys WHERE name = 'jwt_secret'")
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, nil, fmt.Errorf("get jwt keys: %w", err)
	}
	privBlock, _ := pem.Decode(model.Private)
	priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	pubBlock, _ := pem.Decode(model.Public)
	pub, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
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

	_, err := r.db.ExecContext(ctx, "INSERT INTO rsa_keys (name,created_at,private,public) VALUES ('jwt_secret',?,?,?)", time.Now().Unix(), keyPEM, pubPEM)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
			err = repos.ErrKeyExists
		}
		return fmt.Errorf("insert RSA keys: %w", err)
	}
	return nil
}
