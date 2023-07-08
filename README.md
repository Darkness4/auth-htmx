# Go + HTMX + OAuth2

A very simple example HTMX with OAuth2 with:

- Go HTML templating engine.
- HTMX solution for SSR.
- OAuth2 with Github Auth.
- (+CSRF protection measures for OAuth2 and all requests).
- SQLite3 with SQLBoiler and golang-migrate.

## Motivation

For the hype.

## Application Flow

- A home page:
  - Show login button if not logged in.
  - Else, show a welcome with routing.
- A protected counter page.

The login process follows the standard OAuth2 process, which is fully documented on [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).
