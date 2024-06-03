-- +migrate Up
ALTER TABLE users ADD COLUMN admin boolean NOT NULL DEFAULT false;

-- +migrate Down
ALTER TABLE users DROP COLUMN admin;
