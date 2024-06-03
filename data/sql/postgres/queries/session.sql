-- name: FindSession :one
SELECT data FROM sessions WHERE token = $1 AND expires > sqlc.arg(now);
-- name: CommitSession :exec
INSERT INTO sessions (
  token, data, expires
) VALUES (
  $1, $2, $3
)
ON CONFLICT(token) DO UPDATE SET token = $1, data = $2, expires = $3;
-- name: FindSessions :many
SELECT token,data FROM sessions WHERE expires > sqlc.arg(now);
-- name: DeleteSession :exec
DELETE FROM sessions WHERE token = $1;
