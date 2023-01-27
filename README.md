# H-ID

## Description

H-ID is an identity service for H-* applications.

## Setup

### Prerequisites

- [Go](https://go.dev/) 1.19+
- [sql-migrate](https://github.com/rubenv/sql-migrate)
- gcc

### Apply database migrations

```sh
sql-migrate up
```

### Run the webserver

```sh
go run ./cmd/web
```

## License

Copyright (c) 2022 Julian Hofmann

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
