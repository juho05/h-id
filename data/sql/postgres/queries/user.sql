-- name: FindUsers :many
SELECT * FROM users;
-- name: FindUser :one
SELECT * FROM users WHERE id = $1;
-- name: FindUserByEmail :one
SELECT * FROM users WHERE email = $1;
-- name: FindUserByChangeEmailToken :one
SELECT * FROM users WHERE new_email_token = $1 AND new_email_expires > sqlc.arg(now);
-- name: GetUserPasswordHash :one
SELECT password_hash FROM users WHERE id = $1;
-- name: GetOTP :one
SELECT otp_active,otp_url FROM users WHERE id = $1;
-- name: CreateUser :one
INSERT INTO users (
  id, created_at, name, email, email_confirmed, password_hash, otp_active, otp_url
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;
-- name: UpdateUserName :execresult
UPDATE users SET name = $1 WHERE id = $2;
-- name: UpdatePassword :execresult
UPDATE users SET password_hash = $1 WHERE id = $2;
-- name: UpdateEmailConfirmed :execresult
UPDATE users SET email_confirmed = $1 WHERE id = $2;
-- name: UpdateOTP :execresult
UPDATE users SET otp_active = $1, otp_url = $2 WHERE id = $3;
-- name: SetOTPActive :execresult
UPDATE users SET otp_active = $1 WHERE id = $2;
-- name: CreateChangeEmailRequest :execresult
UPDATE users SET new_email = $1, new_email_token = $2, new_email_expires = $3 WHERE id = $4;
-- name: UpdateEmail :one
UPDATE users SET email = new_email, new_email = NULL, new_email_token = NULL, new_email_expires = NULL WHERE new_email_token = $1 AND new_email_expires > sqlc.arg(now) RETURNING email;
-- name: UpdateAdminStatus :execresult
UPDATE users SET admin = $1 WHERE id = $2;
-- name: CreateRecoveryCode :exec
INSERT INTO recovery_codes (created_at,user_id,code_hash) VALUES ($1,$2,$3);
-- name: CountRecoveryCodes :one
SELECT COUNT(code_hash) FROM recovery_codes WHERE user_id = $1;
-- name: DeleteRecoveryCode :execresult
DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2;
-- name: DeleteRecoveryCodes :execresult
DELETE FROM recovery_codes WHERE user_id = $1;
-- name: DeleteUser :execresult
DELETE FROM users WHERE id = $1;
