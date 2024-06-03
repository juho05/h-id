-- name: CreatePasskey :execresult
INSERT INTO passkeys (
  id, cred_id, name, created_at, user_id, credential
) VALUES (
  $1, $2, $3, $4, $5, $6
);
-- name: UpdatePasskeyCredential :execresult
UPDATE passkeys SET credential = $1 WHERE user_id = $2 AND cred_id = $3;
-- name: FindPasskey :one
SELECT * FROM passkeys WHERE user_id = $1 AND id = $2;
-- name: FindPasskeys :many
SELECT * FROM passkeys WHERE user_id = $1;
-- name: UpdatePasskey :execresult
UPDATE passkeys SET name = $1 WHERE user_id = $2 AND id = $3;
-- name: DeletePasskey :execresult
DELETE FROM passkeys WHERE user_id = $1 AND id = $2;