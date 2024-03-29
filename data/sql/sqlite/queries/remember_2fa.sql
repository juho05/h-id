-- name: CreateRemember2FAToken :exec
INSERT INTO remember_2fa (created_at,user_id,code_hash,expires) VALUES (?,?,?,?);
-- name: DeleteRemember2FAToken :execresult
DELETE FROM remember_2fa WHERE (user_id = ? AND code_hash = ?);
-- name: DeleteRemember2FATokens :execresult
DELETE FROM remember_2fa WHERE user_id = ? OR expires < sqlc.arg(now);
-- name: CheckRemember2FAToken :one
SELECT EXISTS (SELECT * FROM remember_2fa WHERE user_id = ? AND code_hash = ? AND expires > sqlc.arg(now));