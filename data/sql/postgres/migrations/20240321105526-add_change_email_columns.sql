-- +migrate Up
ALTER TABLE users ADD COLUMN new_email text;
ALTER TABLE users ADD COLUMN new_email_token bytea;
ALTER TABLE users ADD COLUMN new_email_expires bigint;

-- +migrate Down
ALTER TABLE users DROP COLUMN new_email;
ALTER TABLE users DROP COLUMN new_email_token;
ALTER TABLE users DROP COLUMN new_email_expires;
