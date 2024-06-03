-- name: FindClient :one
SELECT * FROM clients WHERE id = $1;
-- name: FindClientByUserAndID :one
SELECT * FROM clients WHERE user_id = $1 AND id = $2;
-- name: FindClientByUser :many
SELECT * FROM clients WHERE user_id = $1;
-- name: CreateClient :one
INSERT INTO clients (
  id, created_at, name, description, website, redirect_uris, secret_hash, user_id
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;
-- name: UpdateClient :one
UPDATE clients SET
  name = $1, description = $2, website = $3, redirect_uris = $4
WHERE user_id = $5 AND id = $6
RETURNING *;
-- name: UpdateClientSecret :execresult
UPDATE clients SET secret_hash = $1 WHERE user_id = $2 AND id = $3;
-- name: DeleteClient :execresult
DELETE FROM clients WHERE user_id = $1 AND id = $2;
