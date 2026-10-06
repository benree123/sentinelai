# Free portfolio deployment: Render + Neon

Status: configuration prepared; a live URL is not yet verified.

One Render Docker service serves React, FastAPI, and authenticated WebSockets
from the same HTTPS origin. Neon persists PostgreSQL records independently of
Render's ephemeral filesystem. Keep one process: notifications and rate limits
are process-local. Use fictional portfolio data only.

## Database

Create a dedicated Neon Free project near your Render region. Copy its direct
PostgreSQL connection string privately. Change only `postgresql://` to
`postgresql+psycopg://`, preserving credentials and TLS parameters such as
`sslmode=require`. This selects the installed psycopg driver.

## Application

Create a Render Web Service from `benree123/sentinelai`, branch `main`, using
Docker, the root Dockerfile, and the Free plan. Use `/api/health` as its health
check. Alternatively use the `render.yaml` blueprint. Do not add Render's free
PostgreSQL database, which expires.

Set environment variables privately in Render:

| Variable | Value |
| --- | --- |
| `PORT` | `5090` |
| `SENTINEL_ENV` | `production` |
| `COOKIE_SECURE` | `true` |
| `REQUIRE_EMAIL_VERIFICATION` | `false` for this email-free portfolio demo |
| `DATABASE_URL` | Neon connection using `postgresql+psycopg://` |
| `SENTINEL_JWT_KEY` | Random hexadecimal key, at least 64 characters |
| `SENTINEL_BOOTSTRAP_PASSWORD` | Random private password, 12-128 characters |
| `SENTINEL_PUBLIC_URL` | Exact HTTPS Render service address |

Generate a key with `python -c "import secrets; print(secrets.token_hex(32))"`.
Never commit credentials or share them in screenshots.

First startup seeds admin, manager, analyst, and viewer with the bootstrap
password. Keep it private: it grants administrator access. Do not publish it
as a visitor login. Registration grants viewer access without proving email
ownership. SMTP recovery/invitations and actual local-model inference are not
configured by this deployment. Reviewer access can be arranged separately.

## Verify before sharing

1. Confirm deployment and `/api/health` are healthy over HTTPS.
2. Sign in and confirm session refresh and authenticated WebSockets.
3. Run Account takeover: eleven fictional events and a Critical 95/100 incident.
4. Review evidence and briefing; investigate, contain, and resolve with reasons.
5. Restart the service and confirm database records persist.
6. Confirm unauthenticated users cannot read incidents.
7. Add the verified demo link to README and the repository Website field.

Render Free sleeps after inactivity, so initial loading may be slow. Local
files are ephemeral; use Neon for durable database records. Stay within both
free allowances and do not enable paid upgrades. Plan limits can change.

References: [Render Free](https://render.com/docs/free),
[Neon pricing](https://neon.com/pricing).
