-- +migrate Up
ALTER TABLE users ADD COLUMN otp_active boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN otp_url text NOT NULL DEFAULT '';

-- +migrate Down
ALTER TABLE users DROP COLUMN otp_active;
ALTER TABLE users DROP COLUMN otp_secret;
