package sqlite

import (
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"

	"github.com/Bananenpro/h-id/repos"
)

type DB struct {
	db *sqlx.DB
}

func Connect(connectionString string) (repos.DB, error) {
	db, err := sqlx.Connect("sqlite", connectionString)
	if err != nil {
		return nil, err
	}

	return &DB{
		db: db,
	}, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func newBase() repos.BaseModel {
	return repos.BaseModel{
		ID:        ulid.Make().String(),
		CreatedAt: time.Now().Unix(),
	}
}
