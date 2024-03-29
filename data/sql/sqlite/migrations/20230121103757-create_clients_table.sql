-- +migrate Up
CREATE TABLE clients (
	id TEXT NOT NULL PRIMARY KEY,
	created_at INTEGER NOT NULL,
	name TEXT NOT NULL,
	description TEXT NOT NULL,
	website TEXT NOT NULL,
	redirect_uris BLOB NOT NULL,
	secret_hash BLOB NOT NULL,
	user_id TEXT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE clients;
