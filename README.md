# H-ID

## Description

H-ID is an [OpenID Connect](https://openid.net/connect/) identity provider and auth gateway. It can act as a singe sign-on provider and/or as an auth gateway similar to [Authelia](https://www.authelia.com/).

### Features

- Sign up (with optional invite-only mode)
- Admin accounts
  - user management (invite/view/delete registered users)
- Sign in
  - Email/password authentication
  - 2FA with TOTP and recovery codes
  - Passkeys
  - Forgot password
- Account settings
  - Set/update profile picture
  - Change name/email
- OAuth2 client management
  - every user can register/manage their own clients
- OAuth2/OpenID Connect
  - Authorization Code Flow
  - Available scopes: `openid`, `profile`, `email`
  - Consent dialog (remembered per user-client combination)
- Auth gateway
  - Assign groups to users
  - Allow access per (sub)domain for users/groups

## Installation (Linux with docker-compose)

Create a `h-id` directory and execute these commands in it:
```sh
mkdir ./data
mkdir ./profile-pictures
touch docker-compose.yml
```
Paste the following content into `docker-compose.yml` and change the environment variables to your desired values:
```yml
services:
  h-id:
    image: ghcr.io/juho05/h-id
    restart: unless-stopped
    user: 1000:1000                     # change to your uid:gid combination
    environment:
      - BASE_URL=https://id.example.com    # the URL where you plan to host H-ID
      - BEHIND_PROXY=true               # you should always host H-ID behind a reverse proxy
      - INVITE_ONLY=false               # set to true if you want to disable user sign-up without invitation
      - EMAIL_HOST=<smtp-host>          # SMTP host, e.g. smtp.gmail.com:587
      - EMAIL_USERNAME=<smtp-username>  # SMTP username, e.g. example@gmail.com
      - EMAIL_PASSWORD=<password>       # SMTP password (use an app password if 2FA is activated on your email account)
      - HCAPTCHA_SITE_KEY=<site-key>    # leave blank to disable CAPTCHAs
      - HCAPTCHA_SECRET=<secret>        # leave blank to disable CAPTCHAs
      - SESSION_LIFETIME=24h            # lifetime of user sessions, e.g. 8h15m,96h,15m,86400s (I recommend short durations when H-ID is not used as an auth gateway)
      - SESSION_IDLE_TIMEOUT=4h         # time after which the user is signed out without activity, e.g. 8h15m,96h,15m,86400s (I recommend short durations when H-ID is not used as an auth gateway)
    volumes:
      - ./data:/data
      - ./profile-pictures:/profile_pictures
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile
      - ./caddy/data:/data
      - ./caddy/config:/config
```

To configure the reverse proxy [caddy](https://caddyserver.com/) create a new directory `caddy` in `h-id` and create a file named `Caddyfile` in it with the following content (change `id.example.com` to your domain):
```caddyfile
id.example.com {
  reverse_proxy h-id:8080
}
```

You should now be able to start H-ID by executing the following command in the `h-id` directory:
```sh
docker compose up -d
```

H-ID will be accessible (if you can access port 443 on your server and your domain is properly linked) at `https://<your-domain>`.

You can promote a user to be an administrator with:
```sh
docker compose exec h-id /h-id-cli set-admin user@example.com true # you can also use the user ID instead of the email address
```
This will make the `/admin` endpoint accessible to that user.

To invite a user from the CLI (useful if `INVITE_ONLY` is set before a user was created) execute:
```sh
docker compose exec h-id /h-id-cli invite user@example.com
```

### Auth gateway configuration

To use H-ID as an auth gateway in front of another service make these changes to `docker-compose.yml`:
```yml
services:
  # ...
  h-id:
    # ...
    environment:
      # ...
      - AUTH_GATEWAY_CONFIG=/gateway.json
      - AUTH_GATEWAY_DOMAIN=example.com   # all of your services (including H-ID) must be hosted under this domain/a subdomain
    volumes:
      # ...
      - ./gateway.json:/gateway.json:ro
```

Access rules can be configuraed in `./gateway.json`, e.g.:
```json
{
  "users": {
    "user1": {
      "id": "<user_id>",
      "groups": ["group1"]
    },
    "user2": {
      "id": "<user_id>",
      "groups": ["group1"]
    }
  },
  "domains": {
    "test.example.com": {
      "groups": ["group1"]
    },
    "*.example.com": {
      "users": ["user1"]
    }
  }
}
```

Group/user names can be freely chosen. User IDs must match the ID of the user in H-ID.

Domain names can either be fully qualified or use a `*` as a wildcard to match all subdomains (and sub-subdomains):
```yaml
example.com      # valid
test.example.com # valid
*.example.com    # valid (matches foo.example.com, bar.example.com, foo.bar.example.com, …)

*.*.example.com  # invalid
```

Example configuration to protect a service hosted with Caddy with H-ID:
```caddyfile
my-service.example.com {
  forward_auth h-id:8080 {
    uri /gateway/verify
    copy_headers Remote-User
  }
  reverse_proxy my-service:80
}
```

*Make sure that caddy, my-service and h-id are all on the same Docker network.*

### All options

**Bold**: required

| Name                 | Values                                                       | Default                                                    | Description                                                                                                                    |
|----------------------|--------------------------------------------------------------|------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| **BASE_URL**         | e.g. `https://example.com`, `https://foo.example.com`        | *empty*                                                    | The base URL where H-ID is hosted                                                                                              |
| **EMAIL_HOST**       | e.g. `smpt.google.com:587`                                   | *empty*                                                    | The SMTP host to use for sending emails                                                                                        |
| **EMAIL_USERNAME**   | *string*                                                     | *empty*                                                    | The username of the email account to use for sending emails                                                                    |
| **EMAIL_PASSWORD**   | *string*                                                     | *empty*                                                    | The password (or app password if 2FA is activated on the email account) of the email account to use for sending emails         |
| AUTO_MIGRATE         | `true`/`false`                                               | `true` (Docker), `false` (otherwise)                       | Applies database migrations on start                                                                                           |
| Local                | `true`/`false`                                               | `false`                                                    | Hosts H-ID on `localhost` instead of `0.0.0.0`                                                                                 |
| INVITE_ONLY          | `true`/`false`                                               | `false`                                                    | Requires an invitation to register a new user. Invitations can be sent by an admin at `/admin/user/invite`                     |
| BEHIND_PROXY         | `true`/`false`                                               | `false`                                                    | Uses the `X-Forwarded-For` header instead of the remote IP address for rate limiting                                           |
| PORT                 | 1-65535                                                      | `8080`                                                     | The port H-ID listens on                                                                                                       |
| LOG_LEVEL            | 0-5                                                          | `4`                                                        | The log level of H-IDs logger. Min: 0 (no logs), max: 5 (trace)                                                                |
| LOG_FILE             | filepath, e.g. `./h-id.log`                                  | *STDERR*                                                   | Where to write log messages                                                                                                    |
| LOG_APPEND           | `true`/`false`                                               | `false`                                                    | Whether to append logs to an existing file or replace the file on start                                                        |
| BCRYPT_COST          | >0                                                           | `12`                                                       | The bcrypt cost to use for password hashing (larger values are more secure but lead to longer login times)                     |
| DB_FILE              | filepath, e.g. `./h-id.db`                                   | `/database.sqlite` (Docker), `database.sqlite` (otherwise) | Where the database file is located. The database is created if it does not already exist.                                      |
| SESSION_LIFETIME     | `24h`,`60m`,`3h5m3s`                                         | `72h`                                                      | The lifetime of user sessions. I recommend short values when H-ID is not used as an auth gateway.                              |
| SESSION_IDLE_TIMEOUT | `24h`,`64m`,`3h5m3s`                                         | `24h`                                                      | The time after which users without activity are signed out. I recommend short values when H-ID is not used as an auth gateway. |
| AUTH_GATEWAY_CONFIG  | filepath, e.g. `./gateway.json`                              | *empty*                                                    | The location of the auth gateway config file. Empty file -> access always denied                                               |
| AUTH_GATEWAY_DOMAIN  | domain, e.g. `example.com`, `foo.example.com`                | *domain of H-ID*                                           | The parent domain of H-ID and all services protected by H-ID                                                                   |
| TLS_CERT             | filepath, e.g. `./cert.pem`                                  | *empty*                                                    | Path to a TLS certificate. Empty -> no HTTPS (usually not necessary because TLS is handled by a reverse proxy like Caddy)      |
| TLS_KEY              | filepath, e.g. `./key.pem`                                   | *empty*                                                    | Path to a TLS key. Empty -> no HTTPS (usually not necessary because TLS is handled by a reverse proxy like Caddy)              |
| PROFILE_PICTURE_DIR  | dirpath, e.g. `./profile-pictures`                           | `./profile_pictures`                                       | Directory where profile pictures are stored                                                                                    |
| PROFILE_PICTURE_SIZE | width/height in pixels, e.g. `512`, `1024`, `128`, `2048`, … | `1024`                                                     | The size in pixel at which profile pictures are stored on disk                                                                 |
| HCAPTCHA_SITE_KEY    | *string*                                                     | *empty*                                                    | [hCaptcha](https://www.hcaptcha.com/) site key. Empty -> CAPTCHAs disabled                                                     |
| HCAPTCHA_SECRET      | *string*                                                     | *empty*                                                    | [hCaptcha](https://www.hcaptcha.com/) secret. Empty -> CAPTCHAs disabled                                                       |

## How to update

Execute the following commands in the `h-id` directory:
```sh
docker compose pull h-id caddy
docker compose up -d --force-recreate
```

## How to backup

Simply stop the service with `docker compose down`, back up the `h-id` directory with your favorite backup tool and start H-ID again with `docker compose up -d`.

## Dev/Build

### Prerequisites

- [Go](https://go.dev/)
- [GNU Make](https://www.gnu.org/software/make)

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

### Build and publish Docker container

```sh
docker buildx build --platform linux/arm64,linux/amd64 --tag example.com/username/repo:latest --push .
```

### Clean

```sh
make clean
```

## License

Copyright (c) 2023-2024 Julian Hofmann

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
