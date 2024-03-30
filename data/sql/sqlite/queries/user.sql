-- name: FindUser :one
SELECT * FROM users WHERE id = ?;
-- name: FindUserByEmail :one
SELECT * FROM users WHERE email = ?;
-- name: FindUserByChangeEmailToken :one
SELECT * FROM users WHERE new_email_token = ? AND new_email_expires > sqlc.arg(now);
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
-- name: UpdatePassword :execresult
UPDATE users SET password_hash = ? WHERE id = ?;
-- name: UpdateEmailConfirmed :execresult
UPDATE users SET email_confirmed = ? WHERE id = ?;
-- name: UpdateOTP :execresult
UPDATE users SET otp_active = ?, otp_url = ? WHERE id = ?;
-- name: SetOTPActive :execresult
UPDATE users SET otp_active = ? WHERE id = ?;
-- name: CreateChangeEmailRequest :execresult
UPDATE users SET new_email = ?, new_email_token = ?, new_email_expires = ? WHERE id = ?;
-- name: UpdateEmail :one
UPDATE users SET email = new_email, new_email = NULL, new_email_token = NULL, new_email_expires = NULL WHERE new_email_token = ? AND new_email_expires > sqlc.arg(now) RETURNING email;
-- name: UpdateAdminStatus :execresult
UPDATE users SET admin = ? WHERE id = ?;
-- name: CreateRecoveryCode :exec
INSERT INTO recovery_codes (created_at,user_id,code_hash) VALUES (?,?,?);
-- name: CountRecoveryCodes :one
SELECT COUNT(code_hash) FROM recovery_codes WHERE user_id = ?;
-- name: DeleteRecoveryCode :execresult
DELETE FROM recovery_codes WHERE user_id = ? AND code_hash = ?;
-- name: DeleteRecoveryCodes :execresult
DELETE FROM recovery_codes WHERE user_id = ?;
-- name: DeleteUser :execresult
DELETE FROM users WHERE id = ?;
