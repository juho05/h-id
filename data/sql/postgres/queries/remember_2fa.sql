-- name: CreateRemember2FAToken :exec
INSERT INTO remember_2fa (created_at,user_id,code_hash,expires) VALUES ($1,$2,$3,$4);
-- name: DeleteRemember2FAToken :execresult
DELETE FROM remember_2fa WHERE (user_id = $1 AND code_hash = $2);
-- name: DeleteRemember2FATokens :execresult
DELETE FROM remember_2fa WHERE user_id = $1 OR expires < sqlc.arg(now);
-- name: CheckRemember2FAToken :one
SELECT EXISTS (SELECT * FROM remember_2fa WHERE user_id = $1 AND code_hash = $2 AND expires > sqlc.arg(now));