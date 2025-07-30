Here’s your **README** draft. I had to dig through that beast of a codebase you dumped on me, but I documented the important parts—especially the API interface.

---

# **Secure Node.js Proxy Server**

This project provides a secure, API-key and cookie-authenticated proxy server with user login, subscription validation, and admin token management. It includes features like:

* **Reverse proxying** of requests to a backend target server.
* **Paywall middleware** that checks subscription status via API keys or authentication cookies.
* **Admin APIs** for creating, updating, and managing user subscriptions.
* **Temporary launch tokens** for third-party applications (e.g., WordPress).
* **Rate limiting** to protect from abuse.
* **HTTPS support** with configurable certificates.
* **Login screen** for email/password authentication.

---

## **Table of Contents**

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Environment Variables](#environment-variables)
4. [Server Features](#server-features)
5. [API Endpoints](#api-endpoints)

   * [Admin APIs](#1-admin-apis)
   * [User Auth APIs](#2-user-auth-apis)
   * [Launch Token APIs](#3-launch-token-apis)
6. [Paywall & Authentication](#paywall--authentication)
7. [Proxy Configuration](#proxy-configuration)
8. [Rate Limiting](#rate-limiting)
9. [Running the Server](#running-the-server)

---

## **Requirements**

* Node.js 18+
* MySQL 8+
* OpenSSL for HTTPS (optional, for local cert generation)
* `npm` or `yarn`

---

## **Installation**

```bash
git clone <repo>
cd <repo>
npm install
```

---

## **Environment Variables**

All critical settings are read from `.env`. Here’s a sample configuration:

```env
## Only if using HTTPS
PORT=443
USE_HTTPS=true
TLS_KEY_PATH=key.pem
TLS_CERT_PATH=cert.pem

## Defines the URL that you are proxying to with this paywall
TARGET_URL=http://backend.local/

## Defines the Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=secret
DB_NAME=proxy_db

## Defines the base URL for this paywall
APP_BASE_URL=https://proxy.example.com

## Defines secrets used for seeding tokens
JWT_SECRET=supersecretjwt
ADMIN_SECRET_KEY=superadmin123
```

---

## **Server Features**

* **Health Check**
  Accessible at `GET /healthcheck`, returns `Hello World!`. Useful for load balancers.

* **Static File Serving**
  Public images are served from `/images`.

* **Request Logging**
  Every incoming request logs headers, body, and client details (debug-level verbosity).

* **CORS**
  Configured for `https://testingillusions.com`. Update as needed.

* **MySQL Integration**
  Validates API keys and subscription statuses from a `users` table.

---

## **API Endpoints**

### **1. Admin APIs**

These endpoints require the header:

```
x-admin-secret: <ADMIN_SECRET_KEY>
```

#### **POST /api/generate-token**

Generate or update an API key for a user.

**Request Body:**

```json
{
  "userIdentifier": "user@example.com",
  "subscriptionStatus": "active"
}
```

**Response:**

```json
{
  "userIdentifier": "user@example.com",
  "apiKey": "generated_api_key_here",
  "subscriptionStatus": "active"
}
```

---

#### **POST /api/update-subscription-status**

Update a user’s subscription status.

**Request Body:**

```json
{
  "userIdentifier": "user@example.com",
  "subscriptionStatus": "inactive"
}
```

**Response:**

```json
{
  "userIdentifier": "user@example.com",
  "subscriptionStatus": "inactive",
  "message": "Subscription status updated successfully."
}
```

---

#### **POST /api/register**

Register a new user (email/password).
Requires `x-admin-secret`.

**Request Body:**

```json
{
  "email": "newuser@example.com",
  "password": "securePassword123"
}
```

---

### **2. User Auth APIs**

#### **GET /login**

Displays a Bootstrap-styled login page.

#### **POST /login**

Authenticates the user using email/password and sets an HTTP-only cookie if successful.

---

### **3. Launch Token APIs**

For third-party apps like WordPress.

#### **GET /api/create-launch-token**

**Headers:**

```
Authorization: Bearer <API_KEY>
```

**Response:**

```json
{
  "launch_url": "https://proxy.example.com/auth-launch?token=12345"
}
```

---

#### **GET /auth-launch**

Validates a temporary launch token, sets the auth cookie, and redirects to `/`.

---

## **Paywall & Authentication**

* Requests are validated by:

  1. **JWT Cookie** (set after login or token verification).
  2. **Bearer Token (API Key)** in `Authorization` header.
  3. **Query parameter** `?apiKey=...`.

* If no valid authentication is found, users are redirected to `/login`.

---

## **Proxy Configuration**

* All requests to `/` are proxied to `TARGET_URL`.
* Disallowed file types: `.exe, .zip, .tar, .pdf, .docx, .xls`, etc.
* Response bodies are rewritten to replace `localhost` URLs with the proxy domain.

---

## **Rate Limiting**

* Limit: **100 requests per 15 minutes per IP.**
* Exceeding this limit returns `429 Too Many Requests`.

---

## **Running the Server**

1. Create `.env` file with required variables.
2. Run:

```bash
node server.js
```

3. Access the proxy at `https://localhost:443`.

---

Want me to **add usage examples for every API (with `curl` commands)** and slap on a database schema example for the `users` table?
