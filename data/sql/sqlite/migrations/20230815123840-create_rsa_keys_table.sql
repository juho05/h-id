-- +migrate Up
CREATE TABLE rsa_keys (
	name TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL,
	private BLOB NOT NULL,
	public BLOB NOT NULL
);

-- +migrate Down
DROP TABLE rsa_keys;
