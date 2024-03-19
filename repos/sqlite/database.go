package sqlite

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	migrate "github.com/rubenv/sql-migrate"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/juho05/log"

	hid "github.com/juho05/h-id"
	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/sqlite/db"
)

type DB struct {
	db    *db.Queries
	rawDB *sql.DB
}

func autoMigrate(db *sql.DB) error {
	migrations := &migrate.HttpFileSystemMigrationSource{
		FileSystem: http.FS(hid.SQLiteMigrationsFS),
	}
	log.Trace("Migrating database...")
	n, err := migrate.Exec(db, "sqlite3", migrations, migrate.Up)
	log.Tracef("Applied %d migrations!", n)
	if err != nil {
		return err
	}
	return nil
}

func Connect(connectionString string) (repos.DB, error) {
	rawDB, err := sql.Open("sqlite", connectionString)
	if err != nil {
		return nil, err
	}

	_, err = rawDB.Exec("PRAGMA journal_mode = WAL")
	if err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	_, err = rawDB.Exec("PRAGMA foreign_keys = 1")
	if err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	_, err = rawDB.Exec("PRAGMA busy_timeout = 3000")
	if err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if config.AutoMigrate() {
		err = autoMigrate(rawDB)
		if err != nil {
			return nil, fmt.Errorf("auto migrate: %w", err)
		}
	}

	return &DB{
		db:    db.New(rawDB),
		rawDB: rawDB,
	}, nil
}

func (d *DB) Close() error {
	return d.rawDB.Close()
}

func repoErrResult(format string, result sql.Result, err error) error {
	if err == nil {
		if rows, err := result.RowsAffected(); err == nil && rows == 0 {
			return fmt.Errorf(format, repos.ErrNoRecord)
		}
		return nil
	}
	return repoErr(format, err)
}

func repoErr(format string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = repos.ErrNoRecord
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && (sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY) {
		err = repos.ErrExists
	}
	return fmt.Errorf(format, err)
}

func urlsToJSON(urls []*url.URL) ([]byte, error) {
	strs := make([]string, len(urls))
	for i, u := range urls {
		strs[i] = u.String()
	}
	bytes, err := json.Marshal(strs)
	if err != nil {
		return nil, fmt.Errorf("URLs to JSON: %w", err)
	}
	return bytes, nil
}

func urlsFromJSON(jsn []byte) ([]*url.URL, error) {
	var strs []string
	err := json.Unmarshal(jsn, &strs)
	if err != nil {
		return nil, fmt.Errorf("URLs from JSON: %w", err)
	}
	urls := make([]*url.URL, len(strs))
	for i, s := range strs {
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("URLs from JSON: %w", err)
		}
		urls[i] = u
	}
	return urls, nil
}
