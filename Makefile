OUT_DIR=bin
BIN_NAME=h-id

build:
	go build -o ${OUT_DIR}/${BIN_NAME} ./cmd/web

run:
	go run ./cmd/web

watch:
	@which wgo &> /dev/null || (echo "Installing wgo..." && go install github.com/bokwoon95/wgo@latest)
	wgo run -file .html -file .css -file .js -file .png -file .jpg -file .json -file .env ./cmd/web

migrate-up: sql-migrate
	@sql-migrate up

migrate-down: sql-migrate
	@sql-migrate down


sql-migrate:
	@which sql-migrate &> /dev/null || (echo "Installing sql-migrate..." && go install github.com/rubenv/sql-migrate/...@latest)

clean:
	go clean
	rm -r ${OUT_DIR}
