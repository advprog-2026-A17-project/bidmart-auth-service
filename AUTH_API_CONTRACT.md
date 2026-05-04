# Auth API Contract

Base path: `/api/v1/auth`

## Endpoints

- `POST /api/v1/auth/register`  
  Register user with email, password, and role. Email verification token is issued.

- `POST /api/v1/auth/login`  
  Login with email/password and return access + refresh tokens.

- `POST /api/v1/auth/refresh`  
  Rotate refresh token and issue a new access token pair.

- `POST /api/v1/auth/logout`  
  Revoke current refresh token.

- `GET /api/v1/auth/user`  
  Read sanitized user info by email.

- `GET /api/v1/auth/profile`  
  Read profile data by email.

- `PUT /api/v1/auth/profile`  
  Update profile fields (displayName, avatarUrl, shippingAddress).

- `POST /api/v1/auth/password`
  Set or update password for an account (used for OAuth-only users).

- `POST /api/v1/auth/verify-email`  
  Verify account email using one-time opaque verification token.

- `POST /api/v1/auth/resend-verification`  
  Re-issue verification token for unverified accounts (previous active token invalidated, cooldown enforced).

- `GET /api/v1/auth/sessions`  
  List active refresh-token sessions for an account.

- `POST /api/v1/auth/admin/disable-user`  
  Disable user and revoke all active sessions.

- `POST /api/v1/auth/oauth/login`  
  Google SSO login and token issuance (`provider=google`, `idToken=<google-id-token>`).

- `GET /api/v1/auth/permissions/check`  
  Check if a user has a permission key.

## Token Contract

- Access token: JWT (`Bearer`) with user identity and role claims.
- Refresh token: JWT with rotation on refresh.
- Revocation: refresh token/session revocation on logout and admin disable.

## Email Verification Contract

- Verification tokens are random opaque values and are stored hashed server-side.
- A token is one-time use and becomes invalid once consumed.
- Resending verification invalidates prior active tokens and issues a fresh token.

## Domain Event Contract (Wallet Provisioning)

- Event type: `WalletProvisionRequested.v1`
- Trigger: successful user registration commit
- Delivery pattern: transactional outbox + asynchronous broker publisher

### Payload
```json
{
  "eventId": "uuid",
  "userId": "uuid",
  "email": "user@example.com",
  "occurredAt": "2026-04-16T13:00:00Z",
  "source": "bidmart-auth-service"
}
```

### Retry / idempotency / failure handling

- Auth service stores events in `auth_outbox_events` in the same transaction as user creation.
- Publisher retries failed deliveries with exponential backoff.
- Event transitions:
  - `PENDING` -> first delivery attempt pending
  - `RETRY` -> delivery failed and scheduled for retry
  - `PUBLISHED` -> broker accepted the event
  - `FAILED` -> max attempts exceeded
- Consumers must treat `eventId` (or `userId`) as idempotency keys and handle duplicates safely.