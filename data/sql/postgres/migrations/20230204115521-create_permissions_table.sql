-- +migrate Up
CREATE TABLE permissions (
	created_at bigint NOT NULL,
	client_id text NOT NULL,
	user_id text NOT NULL,
	scopes text NOT NULL,

	PRIMARY KEY (client_id, user_id),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE permissions;
