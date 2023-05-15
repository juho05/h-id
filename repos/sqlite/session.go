package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/juho05/h-id/repos"
)

type sessionRepository struct {
	db *sqlx.DB
}

func (db *DB) NewSessionRepository() repos.SessionRepository {
	return &sessionRepository{
		db: db.db,
	}
}

func (s *sessionRepository) Delete(token string) error {
	return s.DeleteCtx(context.Background(), token)
}

func (s *sessionRepository) Find(token string) ([]byte, bool, error) {
	return s.FindCtx(context.Background(), token)
}

func (s *sessionRepository) Commit(token string, b []byte, expiry time.Time) error {
	return s.CommitCtx(context.Background(), token, b, expiry)
}

func (s *sessionRepository) All() (map[string][]byte, error) {
	return s.AllCtx(context.Background())
}

func (s *sessionRepository) DeleteCtx(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (s *sessionRepository) FindCtx(ctx context.Context, token string) ([]byte, bool, error) {
	var data []byte
	err := s.db.GetContext(ctx, &data, "SELECT data FROM sessions WHERE token = ? AND expires > ?", token, time.Now().Unix())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func (s *sessionRepository) CommitCtx(ctx context.Context, token string, data []byte, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, "REPLACE INTO sessions (token, data, expires) VALUES (?,?,?)", token, data, expires.Unix())
	return err
}

func (s *sessionRepository) AllCtx(ctx context.Context) (map[string][]byte, error) {
	rows, err := s.db.Query("SELECT token, data FROM sessions WHERE expires > ?", time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make(map[string][]byte)
	for rows.Next() {
		var token string
		var data []byte
		err = rows.Scan(&token, &data)
		if err != nil {
			return nil, err
		}
		sessions[token] = data
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return sessions, nil
}
