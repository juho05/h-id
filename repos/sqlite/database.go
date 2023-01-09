package sqlite

import (
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oklog/ulid/v2"

	"github.com/Bananenpro/h-id/repos"
)

type DB struct {
	db *sqlx.DB
}

func Connect(connectionString string) (repos.DB, error) {
	db, err := sqlx.Connect("sqlite3", connectionString)
	if err != nil {
		return nil, err
	}

	return &DB{
		db: db,
	}, nil
}

func newBase() repos.BaseModel {
	return repos.BaseModel{
		ID:        ulid.Make().String(),
		CreatedAt: time.Now(),
	}
}
