-- +migrate Up
CREATE TABLE users (
	id TEXT NOT NULL PRIMARY KEY,
	name TEXT NOT NULL,
	email TEXT NOT NULL UNIQUE,
	email_confirmed INT NOT NULL DEFAULT 0,
	password_hash BLOB NOT NULL
);

-- +migrate Down
DROP TABLE users;
