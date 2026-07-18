-- +migrate Up
ALTER TABLE oauth ADD COLUMN code_challenge text NOT NULL DEFAULT '';

-- +migrate Down
ALTER TABLE oauth DROP COLUMN code_challenge;