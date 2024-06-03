-- name: CreateToken :one
INSERT INTO tokens (
  created_at, category, token_key, value_hash, expires
) VALUES (
  $1, $2, $3, $4, $5
)
ON CONFLICT(category,token_key) DO UPDATE SET created_at = $1, category = $2, token_key = $3, value_hash = $4, expires = $5
RETURNING *;
-- name: FindToken :one
SELECT * FROM tokens WHERE category = $1 AND token_key = $2 AND expires > sqlc.arg(now);
-- name: FindTokenByValue :one
SELECT * FROM tokens WHERE category = $1 AND value_hash = $2 AND expires > sqlc.arg(now);
-- name: DeleteToken :execresult
DELETE FROM tokens WHERE (category = $1 AND token_key = $2) OR expires < sqlc.arg(now);
