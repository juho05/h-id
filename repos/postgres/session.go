package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/postgres/db"
)

type sessionRepository struct {
	db queryStore
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
	return s.db.DeleteSession(ctx, token)
}

func (s *sessionRepository) FindCtx(ctx context.Context, token string) ([]byte, bool, error) {
	data, err := s.db.FindSession(ctx, db.FindSessionParams{
		Token: token,
		Now:   time.Now().Unix(),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func (s *sessionRepository) CommitCtx(ctx context.Context, token string, data []byte, expires time.Time) error {
	return s.db.CommitSession(ctx, db.CommitSessionParams{
		Token:   token,
		Data:    data,
		Expires: expires.Unix(),
	})
}

func (s *sessionRepository) AllCtx(ctx context.Context) (map[string][]byte, error) {
	sessionRows, err := s.db.FindSessions(ctx, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	sessions := make(map[string][]byte, len(sessionRows))
	for _, row := range sessionRows {
		sessions[row.Token] = row.Data
	}
	return sessions, nil
}
