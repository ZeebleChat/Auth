# Zbeam — Authentication Service

**Zbeam** is the identity and authentication service for Zeeble. It handles user registration, login, JWT token issuance, account management, TOTP two-factor authentication, recovery codes, Stripe payments, and social features (friends, server linking).

## Tech Stack

- **Language**: Rust
- **Framework**: Axum (async HTTP/WebSocket)
- **Database**: PostgreSQL (via `sqlx`)
- **Authentication**: Ed25519 signatures for JWTs
- **Rate Limiting**: In-memory store (configurable)
- **Email**: Resend API integration
- **Payments**: Stripe

## Quick Start

### Prerequisites

- Docker + Docker Compose
- PostgreSQL (if not using Docker Compose)
- Rust toolchain (for building from source)

### Using Docker Compose (Recommended)

```bash
cd Auth
cp .env.example .env  # Edit if needed (defaults are fine for local dev)
docker compose up -d
```

This starts:
- **PostgreSQL** on port `5434`
- **Zbeam** on port `8001`

Wait a few seconds for the database to be ready, then check health:

```bash
curl http://localhost:8001/health
# {"status":"ok"}
```

### Running from Source

```bash
cd Auth
cargo run
```

Ensure `DATABASE_URL` and `JWT_PRIVATE_KEY_PATH` are set in your environment or `.env` file.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string (e.g., `postgresql://user:pass@localhost:5432/zbeam_db`) |
| `JWT_PRIVATE_KEY_PATH` | No | `keys/auth-private.pem` | Path to Ed25519 private key PEM file. If not exists, one will be generated automatically. |
| `ALLOWED_ORIGINS` | No | Localhost Tauri variants | Comma-separated CORS allowed origins. For production, set explicitly (e.g., `https://app.zeeble.xyz,https://admin.zeeble.xyz`). |
| `AUTH_RATE_LIMIT_REQUESTS` | No | `10` | Max auth requests (login/register/refresh) per IP per window. |
| `AUTH_RATE_LIMIT_WINDOW_SECS` | No | `60` | Rate limit window in seconds. |
| `ZCLOUD_URL` | No | `http://localhost:8003` | URL of the Cloud service for server management features. |
| `RESEND_API_KEY` | No | — | Resend API key for sending emails (password reset, verification). |
| `STRIPE_SECRET_KEY` | No | — | Stripe secret key for payments. |
| `STRIPE_WEBHOOK_SECRET` | No | — | Stripe webhook signing secret. |
| `STRIPE_PRICE_ID` | No | — | Stripe price ID for subscriptions. |
| `STRIPE_SUCCESS_URL` | No | `http://localhost:5173/success` | Stripe checkout success redirect. |
| `STRIPE_CANCEL_URL` | No | `http://localhost:5173/cancel` | Stripe checkout cancel redirect. |
| `RUST_LOG` | No | `zbeam=info,tower_http=debug` | Log filter. |

## API Endpoints

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | Public JWKS for JWT verification |
| `POST` | `/register` | Create new user account |
| `POST` | `/login` | Authenticate with beam identity + password |
| `POST` | `/refresh` | Refresh access token using refresh token |
| `POST` | `/logout` | Revoke refresh token |
| `POST` | `/validate` | Validate an access token |
| `GET` | `/health` | Health check |

### Account Management (Requires Bearer Token)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/account/info` | Get account details |
| `POST` | `/account/name` | Update display name |
| `POST` | `/account/beam` | Update beam tag (requires re-login) |
| `POST` | `/account/password` | Change password |
| `POST` | `/account/password/reset-pin` | Send password reset PIN to email |
| `POST` | `/account/password/reset` | Reset password with PIN |
| `POST` | `/account/totp/enable` | Enable TOTP 2FA |
| `POST` | `/account/totp/disable` | Disable TOTP |
| `GET` | `/account/totp/setup` | Get TOTP setup secret & QR code |
| `POST` | `/account/recovery-codes/generate` | Generate backup recovery codes |
| `GET` | `/account/recovery-codes/status` | Check if recovery codes exist |
| `POST` | `/account/avatar` | Upload avatar image |
| `POST` | `/account/banner` | Upload profile banner |
| `POST` | `/account/switch_alt` | Switch to an alt account |
| `POST` | `/account/sub` | Create a sub/child account |

### Social Features (Requires Bearer Token)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/social/friends` | List friends |
| `POST` | `/social/friends/request` | Send friend request |
| `POST` | `/social/friends/accept` | Accept friend request |
| `GET` | `/social/servers` | List servers the user is a member of |
| `POST` | `/social/servers/add` | Add user to a server (by invite code) |
| `POST` | `/social/servers/register` | Register a new cloud server |

### Payments (Stripe)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/stripe/checkout` | Create Stripe checkout session |
| `POST` | `/stripe/subscription` | Create subscription |
| `POST` | `/stripe/confirm` | Confirm payment |
| `POST` | `/stripe/webhook` | Stripe webhook endpoint (POST from Stripe) |

### Promo Codes

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/promo/validate` | Validate a promo code |
| `POST` | `/promo/redeem` | Redeem a promo code |

## Authentication

All protected endpoints require an `Authorization: Bearer <access_token>` header. Access tokens are JWTs signed with Ed25519 and are valid for 15 minutes. Use `/refresh` to obtain a new access token using a refresh token.

To validate a token, services can fetch the JWKS from `/.well-known/jwks.json` and verify the signature, `exp`, `iat`, and `beam_identity` claim.

## Beam Identity Format

Beam identities follow the format:

```
displayName<separator>tag
```

| Account Type | Separator | Example |
|--------------|-----------|---------|
| Primary | `»` (U+00BB) | `alice»k4mx9` |
| Alt | `§` (U+00A7) | `alice§ab1cd` |
| Sub/Child | `‡` (U+2021) | `alice‡xyz99` |
| Bot | `λ` (U+03BB) | `MyBotλ00001` |

- `displayName`: 1–12 lowercase letters (a-z), no spaces.
- `tag`: exactly 5 alphanumeric lowercase characters (randomly assigned at registration).
- Maximum length: 18 characters.

## Rate Limiting

Auth endpoints (`/register`, `/login`, `/refresh`) are rate-limited to 10 requests per 60 seconds per IP address by default. This is configurable via `AUTH_RATE_LIMIT_REQUESTS` and `AUTH_RATE_LIMIT_WINDOW_SECS`.

## CORS

For development, CORS allows any `localhost` origin (any scheme/port, including `tauri://localhost`). For production, set `ALLOWED_ORIGINS` to a comma-separated list of exact origins (e.g., `https://app.zeeble.xyz,https://admin.zeeble.xyz`).

## Security Notes

- **JWT Keys**: Ed25519 private key is stored at `JWT_PRIVATE_KEY_PATH`. Rotate by generating a new key and updating the file; the JWKS endpoint will serve the new public key. Old tokens remain valid until expiry.
- **Passwords**: Hashed with bcrypt (cost 12).
- **Database**: SQL injection prevented by using `sqlx` with prepared statements.
- **Email**: Password reset and verification rely on email delivery via Resend. Ensure `RESEND_API_KEY` is set for production.
- **Stripe**: Payments handled by Stripe; never store raw credit card data. Use webhook signature verification (`STRIPE_WEBHOOK_SECRET`).

## Database Schema

Migrations are located in the `migrations/` directory and run automatically on startup. Key tables:

- `users` — user accounts (beam_identity, email, password_hash, totp_enabled, recovery_codes, etc.)
- `sessions` — refresh tokens
- `friends` — friend relationships
- `servers` — cloud server memberships
- `subscriptions` — Stripe subscription records
- `promo_codes` — promo code definitions and redemptions

## Running Tests

```bash
cargo test
```

Unit tests cover auth logic, rate limiting, and helpers. Integration tests are planned.

## Building for Production

```bash
cargo build --release
```

The binary will be located at `target/release/zbeam`.

Dockerfile is provided for containerized deployment.

## Troubleshooting

- **Database connection refused**: Ensure PostgreSQL is running and `DATABASE_URL` is correct. In Docker Compose, `zbeam` depends on `postgres` and will retry automatically.
- **JWKS fetch fails**: Check that `JWT_PRIVATE_KEY_PATH` points to a valid Ed25519 PEM file. The server generates one automatically if missing.
- **Rate limit errors**: Adjust `AUTH_RATE_LIMIT_REQUESTS` and `AUTH_RATE_LIMIT_WINDOW_SECS`. Rate limits are per-IP.
- **CORS errors**: Set `ALLOWED_ORIGINS` to match your client's origin exactly (scheme + host + port).
- **Email not sending**: Set `RESEND_API_KEY` and verify your domain is verified with Resend.

## License

MIT
