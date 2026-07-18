-- name: CreateGatewayToken :exec
INSERT INTO gateway_tokens (created_at, user_id, token_hash, expires) VALUES (?, ?, ?, ?);
-- name: FindGatewayToken :one
SELECT * FROM gateway_tokens WHERE token_hash = ? AND expires > sqlc.arg(now);
-- name: DeleteGatewayToken :execresult
DELETE FROM gateway_tokens WHERE token_hash = ? OR expires < sqlc.arg(now);
-- name: DeleteGatewayTokensByUser :execresult
DELETE FROM gateway_tokens WHERE user_id = ? OR expires < sqlc.arg(now);