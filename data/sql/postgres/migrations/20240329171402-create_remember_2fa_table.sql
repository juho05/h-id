-- +migrate Up
CREATE TABLE remember_2fa (
	created_at bigint NOT NULL,
	user_id text NOT NULL,
	code_hash bytea NOT NULL,
	expires bigint NOT NULL,
  PRIMARY KEY (user_id,code_hash),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE remember_2fa;
