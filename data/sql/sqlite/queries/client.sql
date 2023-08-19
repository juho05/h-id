-- name: FindClient :one
SELECT * FROM clients WHERE id = ?;
-- name: FindClientByUserAndID :one
SELECT * FROM clients WHERE user_id = ? AND id = ?;
-- name: FindClientByUser :many
SELECT * FROM clients WHERE user_id = ?;
-- name: CreateClient :one
INSERT INTO clients (
  id, created_at, name, description, website, redirect_uris, secret_hash, user_id
) VALUES (
  ?, ?, ?, ?, ?, ?, ?, ?  
) RETURNING *;
-- name: UpdateClient :one
UPDATE clients SET
  name = ?, description = ?, website = ?, redirect_uris = ?
WHERE user_id = ? AND id = ?
RETURNING *;
-- name: UpdateClientSecret :execresult
UPDATE clients SET secret_hash = ? WHERE user_id = ? AND id = ?;
-- name: DeleteClient :execresult
DELETE FROM clients WHERE user_id = ? AND id = ?;
