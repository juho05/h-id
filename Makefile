OUT_DIR=bin
BIN_NAME=h-id

.PHONY: build run watch migrate-up migrate-down sql-migrate sqlc-generate clean 

build: sqlc-generate
	CGO_ENABLED=0 go build -o ${OUT_DIR}/${BIN_NAME} ./cmd/web

run: sqlc-generate
	go run ./cmd/web

watch: sqlc-generate
	@which wgo &> /dev/null || (echo "Installing wgo..." && go install github.com/bokwoon95/wgo@latest)
	wgo run -file .html -file .css -file .js -file .png -file .jpg -file .json -file .env ./cmd/web

migrate-up: sql-migrate
	@sql-migrate up

migrate-down: sql-migrate
	@sql-migrate down

sql-migrate:
	@which sql-migrate &> /dev/null || (echo "Installing sql-migrate..." && go install github.com/rubenv/sql-migrate/...@latest)

sqlc-generate:
	@which sqlc &> /dev/null || (echo "Installing sqlc..." && go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest)
	@sqlc generate

clean:
	go clean
	rm -r ${OUT_DIR}
