-- name: CreatePasskey :execresult
INSERT INTO passkeys (
  id, cred_id, name, created_at, user_id, credential
) VALUES (
  ?, ?, ?, ?, ?, ?
);
-- name: UpdatePasskeyCredential :execresult
UPDATE passkeys SET credential = ? WHERE user_id = ? AND cred_id = ?;
-- name: FindPasskey :one
SELECT * FROM passkeys WHERE user_id = ? AND id = ?;
-- name: FindPasskeys :many
SELECT * FROM passkeys WHERE user_id = ?;
-- name: UpdatePasskey :execresult
UPDATE passkeys SET name = ? WHERE user_id = ? AND id = ?;
-- name: DeletePasskey :execresult
DELETE FROM passkeys WHERE user_id = ? AND id = ?;