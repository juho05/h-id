-- +migrate Up
CREATE TABLE permissions (
	created_at INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	user_id TEXT NOT NULL,
	scopes TEXT NOT NULL,

	PRIMARY KEY (client_id, user_id),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE permissions;
