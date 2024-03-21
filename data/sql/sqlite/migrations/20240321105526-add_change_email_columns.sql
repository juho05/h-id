-- +migrate Up
ALTER TABLE users ADD COLUMN new_email TEXT;
ALTER TABLE users ADD COLUMN new_email_token BLOB;
ALTER TABLE users ADD COLUMN new_email_expires INTEGER;

-- +migrate Down
ALTER TABLE users DROP COLUMN new_email;
ALTER TABLE users DROP COLUMN new_email_token;
ALTER TABLE users DROP COLUMN new_email_expires;
