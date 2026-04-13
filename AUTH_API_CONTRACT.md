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

- `POST /api/v1/auth/verify-email`  
  Verify account email using verification token.

- `POST /api/v1/auth/resend-verification`  
  Re-issue verification token for unverified accounts.

- `GET /api/v1/auth/sessions`  
  List active refresh-token sessions for an account.

- `POST /api/v1/auth/admin/disable-user`  
  Disable user and revoke all active sessions.

- `POST /api/v1/auth/oauth/login`  
  OAuth bootstrap login and token issuance.

- `GET /api/v1/auth/permissions/check`  
  Check if a user has a permission key.

## Token Contract

- Access token: JWT (`Bearer`) with user identity and role claims.
- Refresh token: JWT with rotation on refresh.
- Revocation: refresh token/session revocation on logout and admin disable.
