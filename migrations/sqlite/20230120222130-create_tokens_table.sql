-- +migrate Up
CREATE TABLE tokens (
	created_at INTEGER NOT NULL,
	category TEXT NOT NULL,
	token_key TEXT NOT NULL,
	value_hash BLOB NOT NULL,
	expires INTEGER NOT NULL,

	PRIMARY KEY (category, token_key)
);

-- +migrate Down
DROP TABLE tokens;
