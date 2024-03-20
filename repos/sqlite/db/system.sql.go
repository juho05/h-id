// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: system.sql

package db

import (
	"context"
)

const getJWTKeys = `-- name: GetJWTKeys :one
SELECT name, created_at, private, public FROM rsa_keys WHERE name = 'jwt_secret'
`

func (q *Queries) GetJWTKeys(ctx context.Context) (RsaKey, error) {
	row := q.db.QueryRowContext(ctx, getJWTKeys)
	var i RsaKey
	err := row.Scan(
		&i.Name,
		&i.CreatedAt,
		&i.Private,
		&i.Public,
	)
	return i, err
}

const insertJWTKeys = `-- name: InsertJWTKeys :exec
INSERT INTO rsa_keys (
  name,created_at,private,public
) VALUES (
  'jwt_secret',?,?,?
)
`

type InsertJWTKeysParams struct {
	CreatedAt int64
	Private   []byte
	Public    []byte
}

func (q *Queries) InsertJWTKeys(ctx context.Context, arg InsertJWTKeysParams) error {
	_, err := q.db.ExecContext(ctx, insertJWTKeys, arg.CreatedAt, arg.Private, arg.Public)
	return err
}
