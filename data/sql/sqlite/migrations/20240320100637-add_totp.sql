-- +migrate Up
ALTER TABLE users ADD COLUMN otp_active BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN otp_url TEXT NOT NULL DEFAULT '';

-- +migrate Down
ALTER TABLE users DROP COLUMN otp_active;
ALTER TABLE users DROP COLUMN otp_secret;
