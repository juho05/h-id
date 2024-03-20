-- name: FindUser :one
SELECT * FROM users WHERE id = ?;
-- name: FindUserByEmail :one
SELECT * FROM users WHERE email = ?;
-- name: GetUserPasswordHash :one
SELECT password_hash FROM users WHERE id = ?;
-- name: GetOTP :one
SELECT otp_active,otp_url FROM users WHERE id = ?;
-- name: CreateUser :one
INSERT INTO users (
  id, created_at, name, email, email_confirmed, password_hash, otp_active, otp_url
) VALUES (
  ?, ?, ?, ?, ?, ?, ?, ?
) RETURNING *;
-- name: UpdateUserName :execresult
UPDATE users SET name = ? WHERE id = ?;
-- name: UpdateEmailConfirmed :execresult
UPDATE users SET email_confirmed = ? WHERE id = ?;
-- name: UpdateOTP :execresult
UPDATE users SET otp_active = ?, otp_url = ? WHERE id = ?;
-- name: SetOTPActive :execresult
UPDATE users SET otp_active = ? WHERE id = ?;
-- name: DeleteUser :execresult
DELETE FROM users WHERE id = ?;
