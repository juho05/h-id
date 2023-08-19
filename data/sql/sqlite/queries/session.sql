-- name: FindSession :one
SELECT data FROM sessions WHERE token = ? AND expires > sqlc.arg(now);
-- name: CommitSession :exec
REPLACE INTO sessions (
  token, data, expires
) VALUES (
  ?, ?, ?
);
-- name: FindSessions :many
SELECT token,data FROM sessions WHERE expires > sqlc.arg(now);
-- name: DeleteSession :exec
DELETE FROM sessions WHERE token = ?;
