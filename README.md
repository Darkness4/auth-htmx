# Go + HTMX + OAuth2/OIDC

A very simple example HTMX with OAuth2 with:

- Go HTML templating engine.
- HTMX solution for SSR.
- OAuth2 with Github Auth and OIDC.
- (+CSRF protection measures for OAuth2 and all requests).
- SQLite3 with SQLBoiler and golang-migrate.

## Motivation

For the hype.

## Usage

1. Edit the config.yaml to set the OAuth2 providers.

2. Set the necessary parameters or environment variables:

   ```shell
   ## .env.local
   ## A 32 bytes hex secret ()
   CSRF_SECRET=51b22632498f26d9131c4743b72c362567b5b4c96ac5e0f4fef7cb58ecac5684
   ## A unique string secret
   JWT_SECRET=secret
   ## PUBLIC_URL will be used as redirect url which is ${PUBLIC_URL}/callback
   PUBLIC_URL=http://localhost:3000 # redirectURL: http://localhost:3000/callback
   DB_PATH=/data/db.sqlite3
   ```

3. Run the binary:

   ```shell
   ./auth-htmx
   ```

**Help**:

```
NAME:
   auth-htmx - Demo of Auth and HTMX.

USAGE:
   auth-htmx [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --csrf.secret value            A 32 bytes hex secret [$CSRF_SECRET]
   --jwt.secret value             A unique string secret [$JWT_SECRET]
   --config.path value, -c value  Path of the configuration file. (default: "./config.yaml") [$CONFIG_PATH]
   --public-url value             An URL pointing to the server. (default: "http://localhost:3000") [$PUBLIC_URL]
   --db.path value                SQLite3 database file path. (default: "./db.sqlite3") [$DB_PATH]
   --help, -h                     show help
   --version, -v                  print the version
```

## Application Flow

- A home page:
  - Show login button if not logged in.
  - Else, show a welcome with routing.
- A protected counter page.

The login process follows the standard OAuth2 process, which is fully documented on [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).

Fetching identity is through OIDC or GitHub API.
