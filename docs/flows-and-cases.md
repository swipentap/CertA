# CertA: All flows and cases

| # | Auth mode | User / role | Flow | Outcome | UI test |
|---|-----------|-------------|------|---------|--------|
| 1 | OAuth2 on | Has certa client role **admin** | Anonymous → open app → redirect to Login → Challenge → IdP login → callback | Signed in, redirect to app (e.g. Home) | ✅ OAuth2_login_then_logout (uses admin user) |
| 2 | OAuth2 on | No certa **admin** (or no certa roles) | Anonymous → open app → redirect to Login → Challenge → IdP login → callback | OnTokenValidated fails → redirect to **AccessDenied** (never signed in to app) | ✅ OAuth2_login_without_certa_admin_redirects_to_AccessDenied (RequiresOAuth2; set OAUTH2_TEST_USER_NO_ADMIN / OAUTH2_TEST_PASSWORD_NO_ADMIN) |
| 3 | OAuth2 on | Has certa admin | Signed in → click Logout (form POST) | SignOut cookie → redirect to IdP logout URL → IdP redirects back to app | ✅ Same test as 1 |
| 4 | OAuth2 on | On AccessDenied (no certa admin) | User is on /Account/AccessDenied; no app session | No app session; "logout" from app N/A (could still have IdP session) | Covered by case 2 (user lands on AccessDenied) |
| 5 | OAuth2 off (local) | Valid local user (e.g. admin@certa.local) | GET /Account/Login → POST credentials | Signed in, redirect to returnUrl/Home | ✅ After_login_logout_returns_to_home (RequiresLocalAuth; skipped when OAuth2 on) |
| 6 | OAuth2 off | Valid local user | Signed in → click Logout (form POST) | SignOut cookie, redirect to Home | ✅ Same as 5 |
| 7 | OAuth2 off | Invalid credentials | POST Login with wrong email/password | Stay on Login, "Invalid login attempt" | ✅ Local_invalid_login_stays_on_login_with_error (RequiresLocalAuth; skipped when OAuth2 on) |
| 8 | Any | Anonymous | GET /Account/Logout (e.g. address bar) | **405 Method Not Allowed** (action is POST-only) | ✅ GET_Account_Logout_returns_405 |
| 9 | OAuth2 on | Has certa admin | Open /Account/Logout in browser (GET) | 405 Method Not Allowed | ✅ Same as 8 |

**Summary**

- **Flows:** Login (OAuth2/IdP challenge + callback), Login (local POST), Logout (POST), AccessDenied (OnTokenValidated fail), GET Logout (405).
- **Cases:** OAuth2 on/off; when OAuth2 on: user has certa admin vs no certa admin; when local: valid vs invalid credentials; GET vs POST for Logout.
- **UI tests:** All cases have tests. OAuth2 tests need OAUTH2_TEST_USER / OAUTH2_TEST_PASSWORD (admin); no-admin test needs OAUTH2_TEST_USER_NO_ADMIN / OAUTH2_TEST_PASSWORD_NO_ADMIN. Local tests (RequiresLocalAuth) run only when OAuth2 is off (skipped when app redirects to IdP).
