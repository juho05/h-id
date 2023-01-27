-- +migrate Up
CREATE TABLE oauth (
	created_at INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	category TEXT NOT NULL,
	token_hash BLOB NOT NULL,
	redirect_uri TEXT NOT NULL,
	user_id TEXT NOT NULL,
	scopes TEXT NOT NULL,
	data BLOB,
	expires INTEGER NOT NULL,
	used INTEGER NOT NULL,

	PRIMARY KEY (client_id, category, token_hash),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE oauth;
