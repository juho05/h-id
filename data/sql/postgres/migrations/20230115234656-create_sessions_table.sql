-- +migrate Up
CREATE TABLE sessions (
	token text NOT NULL PRIMARY KEY,
	data bytea NOT NULL,
	expires bigint NOT NULL
);

-- +migrate Down
DROP TABLE sessions;
