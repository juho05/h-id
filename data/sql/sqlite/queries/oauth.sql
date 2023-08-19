-- name: CreateOAuthToken :one
INSERT INTO oauth (
  created_at, category, token_hash, redirect_uri, client_id, user_id, scopes, data, expires, used
) VALUES (
  ?,?,?,?,?,?,?,?,?,?
) RETURNING *;
-- name: FindOAuthToken :one
SELECT * FROM oauth WHERE category = ? AND token_hash = ? AND expires > sqlc.arg(now);
-- name: UseOAuthToken :execresult
UPDATE oauth SET used = TRUE WHERE client_id = ? AND category = ? AND token_hash = ?;
-- name: DeleteOAuthToken :execresult
DELETE FROM oauth WHERE (client_id = ? AND category = ? AND token_hash = ?) OR expires < sqlc.arg(now);
-- name: DeleteOAuthTokenByUser :exec
DELETE FROM oauth WHERE (client_id = ? AND user_id = ?) OR expires < sqlc.arg(now);
-- name: SetOAuthPermissions :one
REPLACE INTO permissions (
  created_at,client_id,user_id,scopes
) VALUES (?,?,?,?)
RETURNING *;
-- name: FindOAuthPermissions :one
SELECT * FROM permissions WHERE client_id = ? AND user_id = ?;
-- name: RevokeOAuthPermissions :execresult
DELETE FROM permissions WHERE client_id = ? AND user_id = ?;
