-- +migrate Up
CREATE TABLE recovery_codes (
	created_at bigint NOT NULL,
	user_id text NOT NULL,
	code_hash bytea NOT NULL,
  PRIMARY KEY (user_id,code_hash),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +migrate Down
DROP TABLE recovery_codes;
