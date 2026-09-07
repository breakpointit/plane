# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Microsoft Entra ID (single-tenant) OpenID Connect provider.

Unlike the other Community Edition OAuth providers, identity here is taken from
the ID token rather than from a ``/userinfo`` call: the token is verified against
the tenant's JWKS (signature, issuer, audience, expiry, not-before), and the
``tid`` and ``nonce`` claims are checked explicitly. That removes the need for any
Microsoft Graph permission — the requested scopes stay at ``openid profile email``.

Security boundaries worth keeping in mind when editing this file:

* ``MICROSOFT_TENANT_ID`` is an *identifier*, never a URL. ``validate_tenant_id``
  is the SSRF boundary: every Microsoft URL is built from a fixed host constant,
  and the issuer / JWKS URI taken from the discovery document are re-checked
  against that same host before use.
* The ID token is never decoded without verification. There is no code path that
  disables signature checking or accepts an unsigned token.
* Nothing sensitive is logged: no authorization code, no client secret, no access
  or ID token, no claim values.
"""

# Python imports
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import urlencode, urlparse

# Third party imports
import jwt
import requests
from jwt import PyJWKClient

# Module imports
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value

logger = logging.getLogger("plane.authentication")

# Every Microsoft endpoint is built from this constant. Nothing an administrator
# can type may change the host — that is what keeps the tenant field from turning
# into an SSRF primitive.
MICROSOFT_LOGIN_HOST = "login.microsoftonline.com"
MICROSOFT_LOGIN_ORIGIN = f"https://{MICROSOFT_LOGIN_HOST}"

# Multi-tenant / consumer aliases. This integration is deliberately single tenant,
# so accepting any of these would defeat the tenant check entirely. The GUID is the
# well-known Microsoft account (MSA) tenant.
RESERVED_TENANT_IDS = frozenset({
    "common",
    "organizations",
    "consumers",
    "9188040d-6c67-4c5b-b112-36a304b66dad",
})

_TENANT_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# A verified Entra domain, e.g. "contoso.onmicrosoft.com". The final label must be
# alphabetic, which also rejects bare IP addresses.
_TENANT_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,63}$"
)

# Discovery documents change very rarely; JWKS is cached by PyJWKClient itself.
DISCOVERY_CACHE_TTL = 60 * 60
HTTP_TIMEOUT = 10

_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwk_clients: dict[str, PyJWKClient] = {}
_cache_lock = threading.Lock()


def _configuration_error():
    return AuthenticationException(
        error_code=AUTHENTICATION_ERROR_CODES["MICROSOFT_NOT_CONFIGURED"],
        error_message="MICROSOFT_NOT_CONFIGURED",
    )


def _provider_error():
    """Generic, user-facing failure. Details belong in the server log, not the URL."""
    return AuthenticationException(
        error_code=AUTHENTICATION_ERROR_CODES["MICROSOFT_OAUTH_PROVIDER_ERROR"],
        error_message="MICROSOFT_OAUTH_PROVIDER_ERROR",
    )


def is_microsoft_enabled():
    """Whether an administrator has actually turned Microsoft authentication on."""
    (IS_MICROSOFT_ENABLED,) = get_configuration_value(
        [{"key": "IS_MICROSOFT_ENABLED", "default": os.environ.get("IS_MICROSOFT_ENABLED", "0")}]
    )
    return IS_MICROSOFT_ENABLED == "1"


def validate_tenant_id(tenant_id):
    """
    Return the normalized tenant identifier, or raise MICROSOFT_NOT_CONFIGURED.

    Accepts a directory (tenant) GUID or a verified domain such as
    ``contoso.onmicrosoft.com``. Anything carrying a scheme, path, credential or
    whitespace is rejected before it can reach a URL, and the multi-tenant
    aliases are rejected because this integration is single tenant by design.
    """
    if not tenant_id or not isinstance(tenant_id, str):
        raise _configuration_error()

    tenant_id = tenant_id.strip()

    if tenant_id.lower() in RESERVED_TENANT_IDS:
        raise _configuration_error()

    if _TENANT_GUID_RE.match(tenant_id):
        return tenant_id.lower()

    if _TENANT_DOMAIN_RE.match(tenant_id):
        return tenant_id.lower()

    raise _configuration_error()


def _assert_microsoft_url(url):
    """Confirm a URL taken from the discovery document still points at Microsoft."""
    parsed = urlparse(url or "")
    if parsed.scheme != "https" or parsed.hostname != MICROSOFT_LOGIN_HOST:
        raise _provider_error()
    return url


def get_openid_metadata(tenant_id):
    """
    Fetch (and cache) the tenant's OpenID configuration.

    Only ``issuer`` and ``jwks_uri`` are used; the authorize and token endpoints
    are built from the fixed host template instead, so a malformed or unexpected
    discovery document can never redirect the flow somewhere else.
    """
    now = time.monotonic()
    with _cache_lock:
        cached = _discovery_cache.get(tenant_id)
        if cached and cached[0] > now:
            return cached[1]

    url = f"{MICROSOFT_LOGIN_ORIGIN}/{tenant_id}/v2.0/.well-known/openid-configuration"
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        document = response.json()
    except (requests.RequestException, ValueError) as e:
        logger.warning("Microsoft OIDC discovery failed: %s", type(e).__name__)
        raise _provider_error()

    issuer = document.get("issuer")
    jwks_uri = document.get("jwks_uri")
    if not issuer or not jwks_uri:
        logger.warning("Microsoft OIDC discovery document is missing issuer or jwks_uri")
        raise _provider_error()

    _assert_microsoft_url(issuer)
    _assert_microsoft_url(jwks_uri)

    metadata = {"issuer": issuer, "jwks_uri": jwks_uri}
    with _cache_lock:
        _discovery_cache[tenant_id] = (now + DISCOVERY_CACHE_TTL, metadata)
    return metadata


def get_jwk_client(jwks_uri):
    """One cached PyJWKClient per JWKS URI so signing keys are not refetched per login."""
    with _cache_lock:
        client = _jwk_clients.get(jwks_uri)
        if client is None:
            client = PyJWKClient(jwks_uri, cache_jwk_set=True, lifespan=DISCOVERY_CACHE_TTL, timeout=HTTP_TIMEOUT)
            _jwk_clients[jwks_uri] = client
        return client


def tenant_guid_from_issuer(issuer):
    """
    Extract the directory GUID from a tenant-scoped issuer.

    Microsoft's v2.0 issuer is ``https://login.microsoftonline.com/{guid}/v2.0``
    even when the tenant was addressed by domain, so this is what lets the ``tid``
    claim be compared exactly regardless of which form the administrator typed.
    """
    segments = [segment for segment in urlparse(issuer).path.split("/") if segment]
    if segments and _TENANT_GUID_RE.match(segments[0]):
        return segments[0].lower()
    return None


def generate_code_verifier():
    """RFC 7636 code verifier: 43-128 chars of unreserved characters."""
    return secrets.token_urlsafe(64)


def generate_code_challenge(code_verifier):
    """S256 challenge. `plain` is never used."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def generate_nonce():
    return secrets.token_urlsafe(32)


class MicrosoftOAuthProvider(OauthAdapter):
    provider = "microsoft"
    # Minimal OIDC scopes. `offline_access` is deliberately absent: Plane only needs
    # to identify the user at sign-in, so no refresh token is ever issued or stored.
    scope = "openid profile email"

    def __init__(
        self,
        request,
        code=None,
        state=None,
        callback=None,
        nonce=None,
        code_challenge=None,
        code_verifier=None,
    ):
        # A disabled provider must not authenticate anyone, not even via a direct
        # URL. Checked here rather than in the views so it covers the initiation
        # and callback endpoints of both the app and the spaces flow. Upstream's
        # providers gate only the login button; this deliberately fails closed.
        if not is_microsoft_enabled():
            raise _configuration_error()

        (MICROSOFT_TENANT_ID, MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET) = get_configuration_value(
            [
                {
                    "key": "MICROSOFT_TENANT_ID",
                    "default": os.environ.get("MICROSOFT_TENANT_ID"),
                },
                {
                    "key": "MICROSOFT_CLIENT_ID",
                    "default": os.environ.get("MICROSOFT_CLIENT_ID"),
                },
                {
                    "key": "MICROSOFT_CLIENT_SECRET",
                    "default": os.environ.get("MICROSOFT_CLIENT_SECRET"),
                },
            ]
        )

        if not (MICROSOFT_TENANT_ID and MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET):
            raise _configuration_error()

        # Raises MICROSOFT_NOT_CONFIGURED for anything that is not a plain tenant
        # identifier, before the value is ever interpolated into a URL.
        self.tenant_id = validate_tenant_id(MICROSOFT_TENANT_ID)
        self.nonce = nonce
        self.code_verifier = code_verifier

        client_id = MICROSOFT_CLIENT_ID
        client_secret = MICROSOFT_CLIENT_SECRET

        self.token_url = f"{MICROSOFT_LOGIN_ORIGIN}/{self.tenant_id}/oauth2/v2.0/token"
        authorize_url = f"{MICROSOFT_LOGIN_ORIGIN}/{self.tenant_id}/oauth2/v2.0/authorize"

        redirect_uri = (
            f"""{"https" if request.is_secure() else "http"}://{request.get_host()}/auth/microsoft/callback/"""
        )
        url_params = {
            "client_id": client_id,
            "response_type": "code",
            "response_mode": "query",
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "state": state,
        }
        if nonce:
            url_params["nonce"] = nonce
        if code_challenge:
            url_params["code_challenge"] = code_challenge
            url_params["code_challenge_method"] = "S256"
        auth_url = f"{authorize_url}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            # Identity comes from the validated ID token, so the OIDC userinfo
            # endpoint is never called and no Graph scope is needed.
            None,
            client_secret,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "grant_type": "authorization_code",
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
        }
        if self.code_verifier:
            data["code_verifier"] = self.code_verifier

        token_response = self.get_user_token(data=data, headers={"Accept": "application/json"})

        id_token = token_response.get("id_token")
        if not id_token:
            logger.warning("Microsoft token response did not contain an id_token")
            raise _provider_error()

        self.id_token_claims = self._validate_id_token(id_token)

        # Plane only needs to identify the user at sign-in. Microsoft credentials are
        # deliberately not persisted: the Account row below records the provider
        # identity, but carries no access token, refresh token or raw ID token.
        super().set_token_data(
            {
                "access_token": "",
                "refresh_token": None,
                "access_token_expired_at": None,
                "refresh_token_expired_at": None,
                "id_token": "",
            }
        )

    def _validate_id_token(self, id_token):
        """
        Fully verify the ID token and return its claims.

        Validates signature (RS256 against the tenant JWKS), issuer, audience,
        expiry and not-before via PyJWT, then checks the tenant (`tid`) and the
        `nonce` created at initiation. Any failure raises the generic provider
        error; the specific reason is logged server-side only.
        """
        metadata = get_openid_metadata(self.tenant_id)
        issuer = metadata["issuer"]

        expected_tenant = tenant_guid_from_issuer(issuer)
        if not expected_tenant:
            logger.warning("Could not resolve a tenant GUID from the Microsoft issuer")
            raise _provider_error()

        try:
            signing_key = get_jwk_client(metadata["jwks_uri"]).get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token,
                key=signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=issuer,
                leeway=60,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": ["exp", "iat", "aud", "iss", "sub"],
                },
            )
        except Exception as e:
            # Covers PyJWT validation errors and JWKS retrieval failures. PyJWT's
            # messages are fixed strings ("Signature verification failed",
            # "Audience doesn't match", ...) and never echo the token itself.
            logger.warning("Microsoft ID token validation failed: %s: %s", type(e).__name__, e)
            raise _provider_error()

        # The configured tenant is a security boundary: an identity from any other
        # directory must not be able to sign in, whatever its email domain says.
        token_tenant = claims.get("tid")
        if not token_tenant or not hmac.compare_digest(str(token_tenant).lower(), expected_tenant):
            logger.warning("Microsoft ID token was issued by an unexpected tenant")
            raise _provider_error()

        if self.nonce:
            token_nonce = claims.get("nonce")
            if not token_nonce or not hmac.compare_digest(str(token_nonce), str(self.nonce)):
                logger.warning("Microsoft ID token nonce did not match the value created at initiation")
                raise _provider_error()

        return claims

    def set_user_data(self):
        claims = getattr(self, "id_token_claims", None)
        if not claims:
            raise _provider_error()

        # Organizational accounts carry `email` only when the user has a mail
        # attribute or the app registration adds it as an optional claim. Fail
        # closed rather than synthesising an address from `preferred_username`
        # or the tenant domain — an invented address could collide with an
        # existing Plane account.
        email = claims.get("email")
        if not email or not isinstance(email, str) or not email.strip():
            logger.warning(
                "Microsoft ID token did not contain an email claim; "
                "add `email` as an optional claim on the Entra app registration"
            )
            raise _provider_error()

        # Stable, immutable external identity: tenant + object id. Email addresses
        # change and must never be the identity key.
        tenant_id = str(claims.get("tid"))
        object_id = claims.get("oid") or claims.get("sub")
        if not object_id:
            logger.warning("Microsoft ID token did not contain an oid or sub claim")
            raise _provider_error()

        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": f"{tenant_id}.{object_id}",
                    "email": email,
                    "first_name": claims.get("given_name") or "",
                    "last_name": claims.get("family_name") or "",
                    "display_name": claims.get("name") or "",
                    "avatar": "",
                    "is_password_autoset": True,
                },
            }
        )
