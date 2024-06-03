-- +migrate Up
CREATE TABLE users (
	id text NOT NULL PRIMARY KEY,
	created_at bigint NOT NULL,
	name text NOT NULL,
	email text NOT NULL UNIQUE,
	email_confirmed boolean NOT NULL DEFAULT false,
	password_hash bytea NOT NULL
);

-- +migrate Down
DROP TABLE users;
