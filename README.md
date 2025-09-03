
# Paywall Proxy

This project is a Node.js/Express-based proxy server with a paywall, user authentication, admin API endpoints, and dynamic proxying to a target backend. It supports HTTPS, MySQL user management, JWT authentication, and rate limiting.

## Features

- **Proxying**: Proxies requests to a configurable backend (`TARGET_URL`).
- **Paywall**: Restricts access to authenticated users with active subscriptions (API key or login).
- **JWT & Cookie Auth**: Auth via API key, JWT cookie, or login form.
- **Admin API**: Endpoints for user/token management, protected by an admin secret.
- **Rate Limiting**: Prevents abuse with configurable limits.
- **MySQL Integration**: User, API key, and subscription status stored in MySQL.
- **HTTPS Support**: Loads certificates from env/config.
- **Static Assets**: Serves images from `/public/images`.
- **CORS**: Configurable for allowed origins.
- **Health Check**: `/healthcheck` endpoint for load balancers.

## Environment Variables

- `PORT` - Port to run the proxy (default: 443)
- `TARGET_URL` - Backend URL to proxy to
- `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` - MySQL connection
- `JWT_SECRET` - Secret for JWT signing
- `ADMIN_SECRET_KEY` - Secret for admin API endpoints
- `TLS_KEY_PATH`, `TLS_CERT_PATH` - Paths to HTTPS certs (optional)
- `USE_HTTPS` - Set to `true` to force HTTPS
- `APP_BASE_URL` - Base URL for launch tokens

## API Endpoints

### Health Check

- `GET /healthcheck` — Returns `Hello World!` for load balancer health checks.

### Paywall & Authentication

- **Paywall applies to all routes except:**
	- `/assets/`, `/css/`, `/js/`, `/images/`, `/favicon.ico`, `/api/generate-token`, `/api/update-subscription-status`, `/app/modules/tba/`

#### Login
- `GET /login` — Returns a login form (email/password).
- `POST /login` — Authenticates user, sets JWT cookie if successful.

#### Register (Admin Only)
- `POST /api/register` — Registers a new user (email/password). Requires `x-admin-secret` header or `adminSecret` query param.
	- **Body:** `email`, `password`
	- **Response:** `{ message, email, apiKey, subscriptionStatus }`

### Admin API (Requires `x-admin-secret` header or `adminSecret` query param)

- `POST /api/generate-token` — Generate or update an API key for a user.
	- **Body:** `userIdentifier` (required), `subscriptionStatus` (optional, default: 'active')
	- **Response:** `{ userIdentifier, apiKey, subscriptionStatus }`

- `POST /api/update-subscription-status` — Update a user's subscription status.
	- **Body:** `userIdentifier`, `subscriptionStatus`
	- **Response:** `{ userIdentifier, subscriptionStatus, message }`

### 3rd Party App Integration (WordPress/Vue Launch)

- `GET /api/create-launch-token` — Generates a temporary launch token for a valid API key (in `Authorization: Bearer ...` header).
	- **Response:** `{ launch_url }`

- `GET /auth-launch?token=...` — Consumes a launch token, sets auth cookie, redirects to `/`.

### Proxy

- All other requests are proxied to the backend (`TARGET_URL`).
- Certain file extensions are blocked (e.g., `.exe`, `.zip`, `.pdf`, `.php`, etc.).
- Some paths are rewritten to add `?format=raw` for specific JS files.
- Response bodies and redirect locations are rewritten to replace `localhost` URLs with the public proxy host.

## Rate Limiting

- 100 requests per 15 minutes per IP (customizable).

## Static Files

- `/images/tba_logo.png` is served from `public/images`.

## Running the Proxy

1. Install dependencies:
	 ```sh
	 npm install
	 ```
2. Set up your `.env` file with the required variables.
3. Start the server:
	 ```sh
	 node Proxy.js
	 ```

## License

MIT
