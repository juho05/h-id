-- +migrate Up
CREATE TABLE tokens (
	created_at bigint NOT NULL,
	category text NOT NULL,
	token_key text NOT NULL,
	value_hash bytea NOT NULL,
	expires bigint NOT NULL,

	PRIMARY KEY (category, token_key)
);

-- +migrate Down
DROP TABLE tokens;
