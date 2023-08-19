-- name: FindUser :one
SELECT * FROM users WHERE id = ?;
-- name: FindUserByEmail :one
SELECT * FROM users WHERE email = ?;
-- name: GetUserPasswordHash :one
SELECT password_hash FROM users WHERE id = ?;
-- name: CreateUser :one
INSERT INTO users (
  id, created_at, name, email, email_confirmed, password_hash
) VALUES (
  ?, ?, ?, ?, ?, ?
) RETURNING *;
-- name: UpdateUserName :execresult
UPDATE users SET name = ? WHERE id = ?;
-- name: UpdateEmailConfirmed :execresult
UPDATE users SET email_confirmed = ? WHERE id = ?;
-- name: DeleteUser :execresult
DELETE FROM users WHERE id = ?;
