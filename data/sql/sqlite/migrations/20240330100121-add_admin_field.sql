-- +migrate Up
ALTER TABLE users ADD COLUMN admin BOOLEAN NOT NULL DEFAULT 0;

-- +migrate Down
ALTER TABLE users DROP COLUMN admin;
