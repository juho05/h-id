-- name: GetJWTKeys :one
SELECT * FROM rsa_keys WHERE name = 'jwt_secret';
-- name: InsertJWTKeys :exec
INSERT INTO rsa_keys (
  name,created_at,private,public
) VALUES (
  'jwt_secret',$1,$2,$3
);
