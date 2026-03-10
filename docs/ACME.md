# CertA ACME Server

CertA implements an RFC 8555-compliant ACME server so external clients (Certbot, Caddy, Traefik, etc.) can obtain certificates from CertA via the standard ACME protocol.

## Endpoints

- **Directory:** `GET /acme/directory` - Returns ACME directory with endpoint URLs
- **newNonce:** `GET /acme/newNonce` - Returns fresh nonce in `Replay-Nonce` header
- **newAccount:** `POST /acme/newAccount` - Create or retrieve ACME account
- **newOrder:** `POST /acme/newOrder` - Create certificate order
- **order:** `POST /acme/order/{orderId}` - Get order status (POST-as-GET)
- **finalize:** `POST /acme/order/{orderId}/finalize` - Submit CSR to finalize order
- **certificate:** `POST /acme/order/{orderId}/certificate` - Download issued certificate
- **authz:** `GET /acme/authz/{authId}` - Get authorization status
- **chall:** `POST /acme/chall/{challengeId}` - Trigger challenge validation

## Challenge Types

- **HTTP-01** only (DNS-01 not implemented)

## Configuration

In `appsettings.json`:

```json
{
  "Acme": {
    "Enabled": true,
    "DirectoryBaseUrl": "",
    "SystemUserId": "",
    "HttpChallengeTimeoutSeconds": 30
  }
}
```

- **DirectoryBaseUrl**: Base URL for directory links (e.g. `https://certa.example.com`). If empty, derived from request.
- **SystemUserId**: User ID to own ACME-issued certificates. If empty, uses `admin@certa.local`.
- **HttpChallengeTimeoutSeconds**: Timeout for HTTP-01 validation fetch.

## Usage

1. Point your ACME client at `https://<certa-host>/acme/directory`.
2. Example with Certbot (standalone mode, domain must be reachable):
   ```bash
   certbot certonly --standalone -d example.com \
     --server https://localhost:8443/acme/directory \
     --no-verify-ssl
   ```

## Database

ACME uses these tables (see `Scripts/acme-schema.sql`):

- `AcmeAccounts` - Account key (JWK) and thumbprint
- `AcmeOrders` - Orders and certificate links
- `AcmeAuthorizations` - Per-identifier authorizations
- `AcmeChallenges` - HTTP-01 challenge tokens
- `AcmeNonces` - Replay protection nonces

## Security

- ACME endpoints allow anonymous access (no cookie auth). Authentication is via JWS with account key.
- When OAuth2 is enabled, ACME controller uses `[AllowAnonymous]` so clients can reach it without login.
