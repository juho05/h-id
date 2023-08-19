-- name: CreateToken :one
REPLACE INTO tokens (
  created_at, category, token_key, value_hash, expires
) VALUES (
  ?, ?, ?, ?, ?
) RETURNING *;
-- name: FindToken :one
SELECT * FROM tokens WHERE category = ? AND token_key = ? AND expires > sqlc.arg(now);
-- name: DeleteToken :execresult
DELETE FROM tokens WHERE (category = ? AND token_key = ?) OR expires < sqlc.arg(now);
