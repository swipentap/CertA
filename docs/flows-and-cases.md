# CertA: All flows and cases

| # | Auth mode | User / role | Flow | Outcome | UI test |
|---|-----------|-------------|------|---------|--------|
| 1 | Keycloak on | Has certa client role **admin** | Anonymous → open app → redirect to Login → Challenge → Keycloak login → callback | Signed in, redirect to app (e.g. Home) | ✅ OAuth2_login_then_logout (uses admin user) |
| 2 | Keycloak on | No certa **admin** (or no certa roles) | Anonymous → open app → redirect to Login → Challenge → Keycloak login → callback | OnTokenValidated fails → redirect to **AccessDenied** (never signed in to app) | ✅ OAuth2_login_without_certa_admin_redirects_to_AccessDenied (RequiresKeycloak; set KEYCLOAK_TEST_USER_NO_ADMIN / KEYCLOAK_TEST_PASSWORD_NO_ADMIN) |
| 3 | Keycloak on | Has certa admin | Signed in → click Logout (form POST) | SignOut cookie → redirect to Keycloak logout URL → Keycloak redirects back to app | ✅ Same test as 1 |
| 4 | Keycloak on | On AccessDenied (no certa admin) | User is on /Account/AccessDenied; no app session | No app session; "logout" from app N/A (could still have Keycloak session) | Covered by case 2 (user lands on AccessDenied) |
| 5 | Keycloak off (local) | Valid local user (e.g. admin@certa.local) | GET /Account/Login → POST credentials | Signed in, redirect to returnUrl/Home | ✅ After_login_logout_returns_to_home (RequiresLocalAuth; skipped when Keycloak on) |
| 6 | Keycloak off | Valid local user | Signed in → click Logout (form POST) | SignOut cookie, redirect to Home | ✅ Same as 5 |
| 7 | Keycloak off | Invalid credentials | POST Login with wrong email/password | Stay on Login, "Invalid login attempt" | ✅ Local_invalid_login_stays_on_login_with_error (RequiresLocalAuth; skipped when Keycloak on) |
| 8 | Any | Anonymous | GET /Account/Logout (e.g. address bar) | **405 Method Not Allowed** (action is POST-only) | ✅ GET_Account_Logout_returns_405 |
| 9 | Keycloak on | Has certa admin | Open /Account/Logout in browser (GET) | 405 Method Not Allowed | ✅ Same as 8 |

**Summary**

- **Flows:** Login (Keycloak challenge + callback), Login (local POST), Logout (POST), AccessDenied (OnTokenValidated fail), GET Logout (405).
- **Cases:** Keycloak on/off; when Keycloak on: user has certa admin vs no certa admin; when local: valid vs invalid credentials; GET vs POST for Logout.
- **UI tests:** All cases have tests. Keycloak tests need KEYCLOAK_TEST_USER / KEYCLOAK_TEST_PASSWORD (admin); no-admin test needs KEYCLOAK_TEST_USER_NO_ADMIN / KEYCLOAK_TEST_PASSWORD_NO_ADMIN. Local tests (RequiresLocalAuth) run only when Keycloak is off (skipped when app redirects to Keycloak).
