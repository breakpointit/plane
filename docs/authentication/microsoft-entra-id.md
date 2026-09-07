# Microsoft Entra ID authentication

Native single-tenant Microsoft Entra ID (formerly Azure AD) sign-in for this fork of
Plane Community Edition. It sits alongside the built-in Google, GitHub, GitLab and
Gitea providers and reuses Plane's existing session, user-provisioning and instance
configuration machinery.

> All identifiers in this document are placeholders. Replace `plane.example.com`,
> `contoso.onmicrosoft.com` and the all-zero GUIDs with your own values, and never
> commit a real client secret to a repository.

## What it does

- OAuth 2.0 **authorization code** flow with **PKCE (S256)** against the Microsoft
  identity platform **v2.0** endpoints, scoped to a single configured tenant.
- Identity comes from the **ID token**, fully verified against the tenant's JWKS.
- Requested scopes are `openid profile email` only — **no Microsoft Graph
  permissions**, so no admin consent for Graph is required.
- Microsoft access and refresh tokens are **not stored**. Plane only needs to
  identify the user at sign-in.

## 1. Create the Entra app registration

In the [Microsoft Entra admin center](https://entra.microsoft.com) →
**Identity** → **Applications** → **App registrations** → **New registration**:

| Setting                 | Value                                                              |
| ----------------------- | ------------------------------------------------------------------ |
| Name                    | `Plane` (anything you like)                                        |
| Supported account types | **Accounts in this organizational directory only (Single tenant)** |
| Redirect URI platform   | **Web**                                                            |
| Redirect URI            | `https://plane.example.com/auth/microsoft/callback/`               |

The redirect URI must match **exactly**, including the scheme, host, and the
**trailing slash**. Use the value Plane shows you in God Mode (see step 3) rather
than typing it by hand.

Do **not** enable implicit grant or ID-token implicit flow — this integration uses
the authorization code flow exclusively.

From the app's **Overview** page, note:

- **Directory (tenant) ID** — e.g. `00000000-0000-0000-0000-000000000000`
- **Application (client) ID** — e.g. `00000000-0000-0000-0000-000000000000`

### Client secret

Under **Certificates & secrets** → **Client secrets** → **New client secret**,
create a secret and copy its **Value** (not the Secret ID). The value is shown once
and cannot be retrieved later.

Entra client secrets expire. Note the expiry date and rotate the secret in God Mode
before it lapses; sign-in fails once it does.

### The `email` claim (important)

Plane requires a verified email address and will **refuse to sign a user in
without one** rather than invent an address from a username or domain.

Entra only includes an `email` claim when the user has a mail attribute, or when
the app registration asks for it. If sign-in fails with "Microsoft sign-in failed"
and the server log says the ID token contained no email claim, add the claim:

**Token configuration** → **Add optional claim** → token type **ID** → select
**email** → **Add**. Accept the prompt to turn on the required Microsoft Graph
`email` profile permission — this is an OpenID Connect scope, not a Graph API
permission, and grants no access to mailboxes or directory data.

### Required scopes and permissions

| Scope     | Why                                                           |
| --------- | ------------------------------------------------------------- |
| `openid`  | Issues the ID token used for authentication                   |
| `profile` | Supplies `name`, `given_name`, `family_name`                  |
| `email`   | Supplies the verified `email` claim Plane keys the account on |

Nothing else is requested. There is no `User.Read`, no `offline_access`, and no
directory permission of any kind.

## 2. Where the Plane configuration lives

Instance administration only — **God Mode** → **Authentication** →
**Microsoft Entra ID**. It is not exposed in workspace settings or personal
settings, and workspace admins cannot reach it unless they are also instance
administrators. Every read and write goes through Plane's existing
`InstanceAdminPermission` check on the server, so blocking the route in the browser
is not what protects it.

## 3. Configure Plane

| Field                        | Notes                                                                                                                                                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Tenant ID**                | The Directory (tenant) ID, or a verified domain such as `contoso.onmicrosoft.com`. Shared values (`common`, `organizations`, `consumers`) are rejected — this integration is single tenant by design. URLs are rejected. |
| **Client ID**                | The Application (client) ID from the app registration.                                                                                                                                                                   |
| **Client secret**            | The secret **Value**. Stored encrypted; never displayed again.                                                                                                                                                           |
| **Redirect URI**             | Read-only, generated by Plane. Copy it into the app registration.                                                                                                                                                        |
| **Refresh user attributes…** | Optional. When on, name fields are refreshed from the ID token on each sign-in.                                                                                                                                          |

Save, then turn on **Enable Microsoft Entra ID authentication**. The server refuses
to enable the provider unless the tenant ID, client ID and client secret are all
present and the tenant ID is well formed.

Once enabled, the sign-in page shows a **Continue with Microsoft** button.

Turning the toggle back off both removes the button and disables the authentication
endpoints outright — stored credentials are kept, but no one can sign in with
Microsoft until it is re-enabled.

### Client secret handling

The client secret is **write-only**. After it is saved:

- The God Mode API returns a masked placeholder (`••••••••••••`), never the value.
  This differs from Plane's other providers, which return their secrets in
  cleartext to the administrator's browser.
- Leaving the field untouched when you save keeps the stored secret.
- Typing a new value replaces it.
- The secret is never included in `GET /api/instances/`, the login page, or any
  log line.

## 4. Environment variables

The same four keys can be supplied as environment variables, which is how Docker
and Kubernetes deployments inject the secret from a `Secret`:

```
IS_MICROSOFT_ENABLED=1
MICROSOFT_TENANT_ID=00000000-0000-0000-0000-000000000000
MICROSOFT_CLIENT_ID=00000000-0000-0000-0000-000000000000
MICROSOFT_CLIENT_SECRET=<from your secret store>
ENABLE_MICROSOFT_SYNC=0
```

Precedence follows the existing provider convention exactly — nothing new was
invented here:

- **`SKIP_ENV_VAR=1` (the default).** Configuration lives in the database. On first
  boot the `configure_instance` management command seeds each missing key from the
  environment; after that the **database value wins** and the environment is
  ignored. Change values in God Mode.
- **`SKIP_ENV_VAR=0`.** The environment is read on every request and **always
  overrides** the database. God Mode edits will appear to have no effect.

Upgrading an existing instance is safe: the new keys are created on the next boot
with `IS_MICROSOFT_ENABLED=0`, so nothing changes until an administrator turns it
on. No database migration is involved — these are configuration rows, not schema.

## 5. How the sign-in flow works

1. The user clicks **Continue with Microsoft**. The browser goes to Plane's own
   `/auth/microsoft/` endpoint — it never builds a Microsoft URL itself.
2. Plane generates a `state`, a `nonce` and a PKCE `code_verifier`, stores them in
   the session, and redirects to
   `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`.
3. Entra authenticates the user — including any Conditional Access and MFA policies
   — and redirects back to `/auth/microsoft/callback/` with a code.
4. Plane validates the returned `state` (constant-time, single-use, 10-minute TTL),
   exchanges the code at the tenant token endpoint using the client secret and the
   PKCE verifier, and receives an ID token.
5. The ID token is verified in full: RS256 signature against the tenant's JWKS
   (discovered from the tenant's OpenID configuration), issuer, audience, expiry,
   not-before, the `tid` tenant claim, and the `nonce`.
6. The user is matched or provisioned through Plane's normal flow and a standard
   Plane session is established.

### First sign-in and onboarding

Identity details come from the ID token, so a new user should not be asked to retype
them:

- `email` becomes the account address.
- `given_name` / `family_name` become first and last name. Entra does not populate
  these for every directory profile, so Plane falls back to splitting the `name`
  claim on the first space (`"Ada Lovelace"` → `Ada` / `Lovelace`). A single-word
  name becomes the first name with an empty last name.
- Plane's profile onboarding step is skipped entirely when there is nothing left to
  ask: a name arrived from Entra and no password is required — which is always the
  case when password sign-in is disabled instance-wide. Users invited to an existing
  workspace therefore land straight in the app.
- Creating a workspace is still required for a user who is not a member of one.
  Invite colleagues to a workspace first and they will skip that step too.

With `ENABLE_MICROSOFT_SYNC` on, name and display name are refreshed from the token
on every sign-in, so Entra remains the source of truth and local edits are replaced.
Leave it off if you want users to manage their own display names in Plane.

### Multi-factor authentication and Conditional Access

Plane implements no MFA of its own and makes no attempt to inspect whether MFA
occurred. Authentication happens entirely at Entra, so Conditional Access, MFA,
device compliance and sign-in risk policies all apply normally and are configured
in Entra, not in Plane.

### Logout

Signing out of Plane ends the **Plane** session only.

Federated single logout is **not implemented**. The user's Microsoft browser
session remains, so clicking "Continue with Microsoft" again may sign them straight
back in without a prompt. On a shared machine, users should sign out of Microsoft
separately. This is a deliberate choice — Plane's provider framework has no
federated-logout abstraction, and a partial implementation would be worse than
none.

## 6. Troubleshooting

Errors shown in the browser are intentionally generic. The specific reason is in
the API server log (`plane.authentication`) and never includes tokens, codes or
secrets.

**`AADSTS50011: The redirect URI specified in the request does not match`**
The app registration's redirect URI differs from what Plane sent. Copy the exact
value from the God Mode **Redirect URI** field, including the trailing slash, and
add it under **Authentication** → **Web** → **Redirect URIs**. `http` vs `https`
and a missing trailing slash are the usual culprits. If Plane sits behind a reverse
proxy, make sure it forwards the original host and scheme.

**`AADSTS700016` / `AADSTS90002`: application or tenant not found**
The tenant ID or client ID is wrong, or the app registration lives in a different
directory. Confirm both on the app's Overview page.

**"Microsoft Entra ID not configured" (error code 5113)**
Plane has no complete credential set, or the tenant ID is malformed. The tenant
field takes a GUID or a verified domain — not a URL, and not `common`.

**"Microsoft sign-in failed" (error code 5114)**
A generic failure. Check the server log for the reason:

| Log line                                            | Cause                                                                                            |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `ID token validation failed: ExpiredSignatureError` | Clock skew between Plane and Microsoft; check NTP on the host.                                   |
| `ID token validation failed: InvalidAudienceError`  | The client ID in Plane does not match the app the token was issued for.                          |
| `ID token validation failed: InvalidIssuerError`    | Tenant mismatch between the configuration and the signing tenant.                                |
| `issued by an unexpected tenant`                    | A valid Microsoft identity from a **different** directory tried to sign in. Working as intended. |
| `nonce did not match`                               | A stale or replayed callback. Start sign-in again.                                               |
| `did not contain an email claim`                    | Add the `email` optional claim (see step 1).                                                     |
| `discovery failed`                                  | Plane cannot reach `login.microsoftonline.com`. Check egress/proxy rules.                        |

**`AADSTS7000215: Invalid client secret provided`**
The secret is wrong or has expired. Create a new one in **Certificates & secrets**
and paste the **Value** into God Mode. Entra secrets expire on a schedule — this is
the most common cause of a working integration failing months later.

**Intermittent `429` with `{"error_code":5900,"error_message":"RATE_LIMIT_EXCEEDED"}`**
Not specific to Entra, but SSO-only instances hit it first. Plane throttles
_anonymous_ API requests at `anon: 30/minute`, keyed on client IP. A single page
load makes several unauthenticated calls, `/api/instances/` is browser-cached for
only 12 seconds, and everyone behind one public egress IP (office NAT, VPN) shares
a single bucket — so a handful of colleagues signing in at the same time exhaust it.
Once a user is authenticated the throttle no longer applies, so it shows up on the
sign-in page rather than inside the app.

Raise it for your deployment:

```
ANON_RATE_LIMIT=600/minute
```

Optionally, set `NUM_PROXIES` to the exact number of reverse proxies that append to
`X-Forwarded-For` so throttling keys on the real client address instead of the whole
forwarded chain. Verify the number before setting it — too low makes every user
share one bucket, too high lets a client supply its own throttle key. Leaving it
unset is safe.

**The button does not appear on the sign-in page**
`IS_MICROSOFT_ENABLED` is off, or the browser cached `/api/instances/`. Saving the
configuration invalidates that cache; a hard refresh clears the client side.

## 7. Security notes

- The tenant is a hard boundary. Every token's `tid` claim is compared against the
  configured tenant, and the issuer is checked independently. Email domain is never
  used as evidence of tenant membership.
- The external identity key is `tenant-id.object-id`, not the email address, so a
  user keeps their Plane account across an email change.
- ID tokens are never decoded without verification, and signature checking cannot be
  disabled. TLS verification is never relaxed.
- Every Microsoft URL is built from a fixed `login.microsoftonline.com` constant.
  The tenant field is validated as an identifier, and the issuer and JWKS URI taken
  from the discovery document are re-checked against that host, so the configuration
  cannot be turned into an SSRF vector. Custom authorization, token, discovery or
  JWKS URLs are not accepted.
- Account association reuses Plane's existing provisioning path. Because the email
  arrives inside a signature-verified ID token from the one configured tenant, it
  carries at least the assurance of Google's `verified_email` check.
- Turning the God Mode toggle off genuinely disables the provider: `/auth/microsoft/`
  and its callback both refuse once `IS_MICROSOFT_ENABLED` is not `1`, even if the
  credentials are still stored and even when the URL is visited directly. (Plane's
  other providers gate only the login button; this fails closed instead.)
- The initiation and callback routes carry no additional per-IP rate limit, matching
  Plane's other OAuth providers. Initiation validates no credentials — it only
  redirects to Microsoft — and the callback is protected by a single-use, 10-minute
  state value. A per-IP throttle here would break sign-in for every user behind a
  shared corporate egress IP, which is the normal case for a single-tenant
  deployment. Brute-force protection for password and magic-code sign-in is
  unchanged and still governed by `AUTHENTICATION_RATE_LIMIT`.
