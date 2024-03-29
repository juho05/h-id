-- +migrate Up
CREATE TABLE passkeys (
	id TEXT NOT NULL PRIMARY KEY,
	cred_id BLOB NOT NULL UNIQUE,
  name TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	user_id TEXT NOT NULL,
  credential BLOB NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE passkeys;
