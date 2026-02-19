# Keycloak (OAuth2 / OpenID Connect) Authentication

CertA can use **Keycloak** as an external identity provider (OAuth2 / OpenID Connect). When enabled, users sign in via Keycloak instead of the built-in login form; CertA still stores user records and links them to Keycloak identities by email.

## Overview

- **Cookie auth (default):** Login form, CertA stores passwords. No Keycloak.
- **Keycloak enabled:** Login redirects to Keycloak; after successful auth, CertA creates or finds a user by email and signs them in with a cookie. Profile and certificate ownership stay in CertA.

First-time Keycloak users are **auto-provisioned**: CertA creates a local user from Keycloak claims (email, name) so they can use CertA normally (profile, certificates). No separate registration in CertA.

## Prerequisites

- Keycloak server (e.g. 21+) with a realm and admin access
- CertA reachable over HTTPS from user browsers (required for OIDC redirects; see Docker notes below)
- From the CertA host/container: network and DNS access to the Keycloak authority URL

---

## 1. Keycloak configuration

### 1.1 Create or choose a realm

Use an existing realm (e.g. `master`) or create one (e.g. `certa`). The **Authority** in CertA must match (see below).

### 1.2 Create a client

1. In Keycloak Admin: **Clients** → **Create client**.
2. **General settings**
   - **Client type:** OpenID Connect  
   - **Client ID:** `certa` (or another ID; must match CertA config)
3. **Capability config**
   - **Client authentication:** On if you want a client secret; Off for public client.
   - **Authorization:** Off (unless you use Keycloak authorization).
   - **Authentication flow:**  
     - **Standard flow:** Enabled (authorization code).  
     - **Direct access grants:** Optional (only if you need it).
4. **Login settings**
   - **Root URL:** Base URL of CertA (e.g. `https://certa.example.com` or `https://localhost:8443`).
   - **Valid redirect URIs:**  
     - Add: `https://<certa-base-url>/signin-oidc`  
     - Example: `https://localhost:8443/signin-oidc` or `https://certa.example.com/signin-oidc`.
   - **Valid post logout redirect URIs:** Optional; add CertA base URL if you use single logout.
   - **Web origins:** Add CertA base URL (e.g. `https://localhost:8443` or `+` for same as redirect).
5. Save.

### 1.3 Client secret (optional)

- If **Client authentication** is On, open the client → **Credentials** and copy the **Client secret** into CertA config (see below).
- If the client is public, leave **Client secret** empty in CertA.

### 1.4 Ensure users have email or username

CertA matches Keycloak users by **email** (or `preferred_username` if email is missing). In your realm, ensure users have **email** or **username** set so CertA can provision/link accounts.

### 1.5 Roles (e.g. Admin) from Keycloak

CertA uses **only the certa client roles** from the Keycloak token for authorization (e.g. `[Authorize(Roles = "Admin")]`). Realm roles are **not** used. Roles are **not** read from the CertA database for Keycloak users.

- **Realm roles:** Add the user to a realm role (e.g. `admin` or `Admin`) in Keycloak. Ensure that role is included in the access token:
  - In Keycloak: **Client** → **certa** → **Client scopes** → open **Dedicated scope** or **Optional client scopes** and ensure the scope that adds realm roles is assigned (e.g. **roles**).
  - In **Client scopes** → **roles** (or the scope that contains realm roles) → **Mappers**: enable a mapper that adds realm roles to the **access token** (e.g. **realm roles** mapper with “Add to ID token” / “Add to access token” as needed).
- **Assign the admin client role:** In **Users** → _user_ → **Role mappings** → **Client roles** dropdown choose **certa** → under **Available roles** select **admin** → **Add selected >**. Only users with the **admin** role assigned for the **certa** client get Admin access in CertA.
- **Name matching:** CertA treats the client role `admin` (lowercase) as `Admin` for `[Authorize(Roles = "Admin")]`.

### 1.6 HTTPS and discovery

- Keycloak should be reachable over **HTTPS** in production. CertA will fetch `/.well-known/openid-configuration` and token/userinfo endpoints from the **Authority** URL.
- If Keycloak is behind a proxy, set **Frontend URL** (or equivalent) so discovery and issuer use HTTPS; otherwise CertA may get `invalid_request` or HTTP URLs in metadata.

---

## 2. CertA configuration

### 2.1 Configuration section

CertA reads Keycloak settings from the **Authentication:Keycloak** section (e.g. `appsettings.json` or environment variables).

| Setting | Description | Example |
|--------|-------------|---------|
| **Enabled** | Use Keycloak when `true`; otherwise use built-in login only. | `true` |
| **Authority** | Keycloak realm URL (no trailing slash). | `https://auth.example.com/realms/myrealm` or `https://auth.dev.net/auth/realms/master` |
| **ClientId** | Keycloak client ID. | `certa` |
| **ClientSecret** | Client secret if client is confidential; empty for public client. | `""` or your secret |
| **CallbackPath** | Path for the OIDC callback; must match Keycloak redirect URI. | `/signin-oidc` |
| **RequireHttpsMetadata** | If `true`, OIDC metadata and endpoints must use HTTPS. Set `false` only for dev with HTTP. | `true` |

### 2.2 appsettings.json example

```json
{
  "Authentication": {
    "Keycloak": {
      "Enabled": true,
      "Authority": "https://auth.example.com/realms/myrealm",
      "ClientId": "certa",
      "ClientSecret": "",
      "CallbackPath": "/signin-oidc",
      "RequireHttpsMetadata": true
    }
  }
}
```

### 2.3 Environment variables (e.g. Docker)

Same keys as above, with `__` for nesting:

```bash
Authentication__Keycloak__Enabled=true
Authentication__Keycloak__Authority=https://auth.example.com/realms/myrealm
Authentication__Keycloak__ClientId=certa
Authentication__Keycloak__ClientSecret=
Authentication__Keycloak__CallbackPath=/signin-oidc
Authentication__Keycloak__RequireHttpsMetadata=true
```

### 2.4 Authority URL format

- Keycloak realm URL is usually:  
  `https://<keycloak-host>/realms/<realm>`  
  or, if Keycloak is under a path:  
  `https://<keycloak-host>/auth/realms/<realm>`
- Use the exact base URL your Keycloak uses for the realm (no trailing slash). CertA will append `/.well-known/openid-configuration` and use the returned endpoints.

---

## 3. Docker deployment notes

### 3.1 HTTPS for CertA

OIDC redirects and callbacks must use a stable, HTTPS URL in production. In Docker:

- CertA is typically configured to listen on HTTPS (e.g. port 8081) with a certificate.
- Publish that port (e.g. `8443:8081`) and use `https://localhost:8443` (or your hostname) as the CertA base URL in Keycloak redirect URIs and Web origins.

### 3.2 DNS and network

- CertA (in the container) must resolve and reach the **Authority** host (e.g. `auth.example.com`). Do **not** override the Authority hostname to `host-gateway` in Docker unless Keycloak actually listens on the host; use normal DNS so the container reaches Keycloak at its real URL (e.g. `10.11.4.17` or a public hostname).

### 3.3 Development: SSL and metadata

For **development only** you may need to relax checks:

- **Backchannel SSL:** CertA uses a backchannel HTTP client to fetch discovery, JWKS, token, and userinfo. If Keycloak uses a self-signed or hostname-mismatch certificate, the app can be configured to skip server certificate validation for that client (development only).
- **RequireHttpsMetadata:** If Keycloak’s discovery document returns HTTP URLs (e.g. behind a proxy), set `RequireHttpsMetadata=false` so the document retriever accepts them. Prefer fixing Keycloak’s frontend URL so it returns HTTPS instead.

### 3.4 Data protection

When running in Docker, ensure the app can write **Data Protection** keys (e.g. into `/app/DataProtection-Keys`). The image should create this directory and set ownership to the app user so cookie encryption works after Keycloak login.

---

## 4. Authorization: Admin role from Keycloak

When Keycloak is enabled, **role claims are taken only from the Keycloak token** (realm roles or client roles), not from CertA’s database. So for a user to be treated as **Admin** in CertA (e.g. access `/Admin` or any `[Authorize(Roles = "Admin")]` action), that user must have the corresponding role in Keycloak and that role must be present in the access token (see section 1.5).

## 5. Flow summary

1. User opens CertA and clicks Login.
2. CertA redirects to Keycloak (authorization endpoint) with `client_id`, `redirect_uri`, scope, etc.
3. User signs in at Keycloak.
4. Keycloak redirects to CertA at `CallbackPath` (e.g. `/signin-oidc`) with an authorization code.
5. CertA exchanges the code for tokens (and optionally userinfo), then runs **OnTokenValidated**.
6. CertA finds or creates a user by email (from token/userinfo), builds a local principal, and signs the user in with a cookie.
7. User is on CertA as that user (profile, certificates).

---

## 6. Troubleshooting

| Issue | What to check |
|-------|----------------|
| **Connection refused** to Authority | DNS from CertA container (e.g. `getent hosts auth.example.com`), firewall, and that Keycloak listens on the expected interface/port. Avoid mapping Authority to `host-gateway` unless Keycloak is on the host and listening on the Docker host IP. |
| **SSL certificate invalid** | Use a valid cert for Keycloak, or (dev only) configure the OIDC backchannel to skip server certificate validation. |
| **IDX20108 / not valid as per HTTPS scheme** | Keycloak discovery returned HTTP URLs. Set `RequireHttpsMetadata=false` or fix Keycloak’s frontend URL so metadata uses HTTPS. |
| **invalid_request / Authentication failed** (during redirect) | Often caused by **Pushed Authorization Requests (PAR)**. CertA uses PAR by default on .NET 9; if Keycloak does not support PAR, disable it in CertA (`PushedAuthorizationBehavior.Disable`). |
| **Redirect URI mismatch** | Keycloak **Valid redirect URIs** must exactly match CertA’s callback URL (scheme, host, path), e.g. `https://localhost:8443/signin-oidc`. |
| **Access to path '.../DataProtection-Keys' is denied** | The app user needs write access to the Data Protection key directory; fix directory creation and ownership in the image. |

---

## 7. Security notes

- Use **HTTPS** for both CertA and Keycloak in production.
- Keep **ClientSecret** confidential and use a confidential client when possible.
- Disabling SSL validation or `RequireHttpsMetadata` is for development only.
- Rely on Keycloak for authentication; CertA still enforces authorization (e.g. user isolation for certificates) using the provisioned user identity.

---

*Last updated: February 2026*
