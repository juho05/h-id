-- name: CreateOAuthToken :one
INSERT INTO oauth (
  created_at, category, token_hash, redirect_uri, client_id, user_id, scopes, data, expires, used
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
) RETURNING *;
-- name: FindOAuthToken :one
SELECT * FROM oauth WHERE category = $1 AND token_hash = $2 AND expires > sqlc.arg(now);
-- name: UseOAuthToken :execresult
UPDATE oauth SET used = TRUE WHERE client_id = $1 AND category = $2 AND token_hash = $3;
-- name: DeleteOAuthToken :execresult
DELETE FROM oauth WHERE (client_id = $1 AND category = $2 AND token_hash = $3) OR expires < sqlc.arg(now);
-- name: DeleteOAuthTokenByUser :exec
DELETE FROM oauth WHERE (client_id = $1 AND user_id = $2) OR expires < sqlc.arg(now);
-- name: SetOAuthPermissions :one
INSERT INTO permissions (
  created_at,client_id,user_id,scopes
) VALUES ($1,$2,$3,$4)
ON CONFLICT(client_id,user_id) DO UPDATE SET created_at = $1, client_id = $2, user_id = $3, scopes = $4
RETURNING *;
-- name: FindOAuthPermissions :one
SELECT * FROM permissions WHERE client_id = $1 AND user_id = $2;
-- name: RevokeOAuthPermissions :execresult
DELETE FROM permissions WHERE client_id = $1 AND user_id = $2;
