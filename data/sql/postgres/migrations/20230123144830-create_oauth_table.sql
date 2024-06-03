-- +migrate Up
CREATE TABLE oauth (
	created_at bigint NOT NULL,
	client_id text NOT NULL,
	category text NOT NULL,
	token_hash bytea NOT NULL,
	redirect_uri text NOT NULL,
	user_id text NOT NULL,
	scopes text NOT NULL,
	data bytea,
	expires bigint NOT NULL,
	used boolean NOT NULL,

	PRIMARY KEY (client_id, category, token_hash),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE oauth;
