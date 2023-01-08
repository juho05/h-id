-- +migrate Up
CREATE TABLE users (
	id TEXT NOT NULL PRIMARY KEY,
	name TEXT NOT NULL,
	email TEXT NOT NULL UNIQUE,
	email_confirmed INTEGER NOT NULL DEFAULT 0,
	password_hash BLOB NOT NULL,
	created TEXT NOT NULL
);

-- +migrate Down
DROP TABLE users;
