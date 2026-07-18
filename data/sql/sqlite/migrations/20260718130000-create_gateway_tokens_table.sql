-- +migrate Up
CREATE TABLE gateway_tokens (
	created_at INTEGER NOT NULL,
	user_id TEXT NOT NULL,
	token_hash BLOB NOT NULL,
	expires INTEGER NOT NULL,
	PRIMARY KEY (token_hash),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX idx_gateway_tokens_user_id ON gateway_tokens (user_id);

-- +migrate Down
DROP TABLE gateway_tokens;