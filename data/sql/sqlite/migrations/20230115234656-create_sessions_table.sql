-- +migrate Up
CREATE TABLE sessions (
	token TEXT NOT NULL PRIMARY KEY,
	data BLOB NOT NULL,
	expires INTEGER NOT NULL
);

-- +migrate Down
DROP TABLE sessions;
