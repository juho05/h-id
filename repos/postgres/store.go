package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/juho05/h-id/repos/postgres/db"
)

type queryStore interface {
	db.Querier
	BeginTransaction(ctx context.Context) (queryStore, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	Close() error
}

type store struct {
	*db.Queries
	db *pgxpool.Pool
}

type transaction struct {
	*db.Queries
	tx pgx.Tx
}

func NewStore(pDB *pgxpool.Pool) (queryStore, error) {
	store := &store{
		db:      pDB,
		Queries: db.New(pDB),
	}
	return store, nil
}

func (s *store) BeginTransaction(ctx context.Context) (queryStore, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	return &transaction{
		Queries: s.Queries.WithTx(tx),
		tx:      tx,
	}, nil
}

func (s *store) Commit(ctx context.Context) error {
	return errors.New("store is not a transaction")
}

func (s *store) Rollback(ctx context.Context) error {
	return errors.New("store is not a transaction")
}

func (s *store) Close() error {
	s.db.Close()
	return nil
}

func (s *transaction) BeginTransaction(ctx context.Context) (queryStore, error) {
	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	return &transaction{
		Queries: s.Queries.WithTx(tx),
		tx:      tx,
	}, nil
}

func (s *transaction) Commit(ctx context.Context) error {
	return s.tx.Commit(ctx)
}

func (s *transaction) Rollback(ctx context.Context) error {
	return s.tx.Rollback(ctx)
}

func (s *transaction) Close() error {
	return nil
}
