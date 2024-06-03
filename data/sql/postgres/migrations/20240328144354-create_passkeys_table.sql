-- +migrate Up
CREATE TABLE passkeys (
	id text NOT NULL PRIMARY KEY,
	cred_id bytea NOT NULL UNIQUE,
  name text NOT NULL,
	created_at bigint NOT NULL,
	user_id text NOT NULL,
  credential bytea NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE passkeys;
