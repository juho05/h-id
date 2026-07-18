-- name: CreateGatewayToken :exec
INSERT INTO gateway_tokens (created_at, user_id, token_hash, expires) VALUES ($1, $2, $3, $4);
-- name: FindGatewayToken :one
SELECT * FROM gateway_tokens WHERE token_hash = $1 AND expires > sqlc.arg(now);
-- name: DeleteGatewayToken :execresult
DELETE FROM gateway_tokens WHERE token_hash = $1 OR expires < sqlc.arg(now);
-- name: DeleteGatewayTokensByUser :execresult
DELETE FROM gateway_tokens WHERE user_id = $1 OR expires < sqlc.arg(now);