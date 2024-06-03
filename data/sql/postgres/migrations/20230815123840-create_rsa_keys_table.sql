-- +migrate Up
CREATE TABLE rsa_keys (
	name text PRIMARY KEY,
	created_at bigint NOT NULL,
	private bytea NOT NULL,
	public bytea NOT NULL
);

-- +migrate Down
DROP TABLE rsa_keys;
