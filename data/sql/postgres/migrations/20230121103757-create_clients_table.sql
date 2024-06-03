-- +migrate Up
CREATE TABLE clients (
	id text NOT NULL PRIMARY KEY,
	created_at bigint NOT NULL,
	name text NOT NULL,
	description text NOT NULL,
	website text NOT NULL,
	redirect_uris bytea NOT NULL,
	secret_hash bytea NOT NULL,
	user_id text NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE clients;
