# H-ID

## Description

H-ID is an [OpenID Connect](https://openid.net/connect/) identity provider for H-* applications.

## Setup

### Prerequisites

- [Go](https://go.dev/) 1.19+
- [GNU Make](https://www.gnu.org/software/make)
- gcc

### Apply database migrations

```sh
make migrate-up
```

### Run the webserver

```sh
make run
```

### Run the webserver with live reload

```sh
make watch
```

### Build

```sh
make
```

### Clean

```sh
make clean
```

## License

Copyright (c) 2023 Julian Hofmann

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
