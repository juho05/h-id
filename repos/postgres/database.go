package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	migrate "github.com/rubenv/sql-migrate"

	"github.com/juho05/log"

	hid "github.com/juho05/h-id"
	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
)

type DB struct {
	db queryStore
}

func ConstructDSN(dbName, host string, port int, user, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, password, host, port, dbName)
}

func autoMigrate(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}
	defer db.Close()
	migrations := &migrate.HttpFileSystemMigrationSource{
		FileSystem: http.FS(hid.PostgresMigrationsFS),
	}
	log.Trace("Migrating database...")
	n, err := migrate.Exec(db, "postgres", migrations, migrate.Up)
	log.Tracef("Applied %d migrations!", n)
	if err != nil {
		return err
	}
	return nil
}

func Connect(dsn string) (repos.DB, error) {
	log.Tracef("Connecting to Postgres database...")
	conn, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("connect DB: %w", err)
	}
	if config.AutoMigrate() {
		err = autoMigrate(dsn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("auto migrate: %w", err)
		}
	}

	store, err := NewStore(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("new store: %w", err)
	}

	return &DB{
		db: store,
	}, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func repoErrResult(format string, result pgconn.CommandTag, err error) error {
	if err == nil {
		if rows := result.RowsAffected(); rows == 0 {
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
	if errors.Is(err, pgx.ErrNoRows) {
		err = repos.ErrNoRecord
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == pgerrcode.UniqueViolation || strings.Contains(pgErr.ConstraintName, "pkey") {
			err = repos.ErrExists
		}
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
