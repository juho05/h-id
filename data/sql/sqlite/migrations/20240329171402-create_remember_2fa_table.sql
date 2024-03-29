-- +migrate Up
CREATE TABLE remember_2fa (
	created_at INTEGER NOT NULL,
	user_id TEXT NOT NULL,
	code_hash BLOB NOT NULL,
	expires INTEGER NOT NULL,
  PRIMARY KEY (user_id,code_hash),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE remember_2fa;
