package sqlite

import (
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oklog/ulid/v2"
	migrate "github.com/rubenv/sql-migrate"
	_ "modernc.org/sqlite"

	"github.com/Bananenpro/log"

	hid "github.com/juho05/h-id"
	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
)

type DB struct {
	db *sqlx.DB
}

func autoMigrate(db *sqlx.DB) error {
	fs, err := fs.Sub(hid.MigrationsFS, "sqlite")
	if err != nil {
		return err
	}
	migrations := &migrate.HttpFileSystemMigrationSource{
		FileSystem: http.FS(fs),
	}
	log.Trace("Migrating database...")
	n, err := migrate.Exec(db.DB, "sqlite3", migrations, migrate.Up)
	log.Tracef("Applied %d migrations!", n)
	if err != nil {
		return err
	}
	return nil
}

func Connect(connectionString string) (repos.DB, error) {
	db, err := sqlx.Connect("sqlite", connectionString)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec("PRAGMA journal_mode = WAL")
	if err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	_, err = db.Exec("PRAGMA foreign_keys = 1")
	if err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if config.AutoMigrate() {
		err = autoMigrate(db)
		if err != nil {
			return nil, fmt.Errorf("auto migrate: %w", err)
		}
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
