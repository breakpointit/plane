# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Shared fixtures for the Microsoft Entra ID provider tests.

Everything here is synthetic: the RSA keypair is generated in-process and never
written to disk, and the tenant / client identifiers are placeholder GUIDs. No
test in this package performs a network request — discovery and JWKS lookups are
patched at the module level.
"""

# Python imports
import time
import uuid

# Third party imports
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

# Module imports
from plane.authentication.provider.oauth import microsoft as microsoft_provider

# Placeholder identifiers. These are not real Entra values.
TENANT_ID = "11111111-1111-4111-8111-111111111111"
OTHER_TENANT_ID = "22222222-2222-4222-8222-222222222222"
CLIENT_ID = "33333333-3333-4333-8333-333333333333"
CLIENT_SECRET = "test-client-secret-not-a-real-value"
OBJECT_ID = "44444444-4444-4444-8444-444444444444"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
JWKS_URI = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"


@pytest.fixture(scope="session")
def rsa_key_pair():
    """An in-memory RSA keypair used to sign test ID tokens."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def sign_id_token(rsa_key_pair):
    """Return a callable that signs a claim set into an RS256 ID token."""
    private_key, _ = rsa_key_pair

    def _sign(claims, key=None, algorithm="RS256"):
        return jwt.encode(claims, key or private_key, algorithm=algorithm, headers={"kid": "test-key"})

    return _sign


@pytest.fixture
def id_token_claims():
    """A minimal but complete set of valid Entra ID token claims."""
    now = int(time.time())

    def _claims(**overrides):
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "subject-identifier",
            "oid": OBJECT_ID,
            "tid": TENANT_ID,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "email": "entra.user@example.com",
            "name": "Entra User",
            "given_name": "Entra",
            "family_name": "User",
        }
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not None}

    return _claims


@pytest.fixture(autouse=True)
def patch_microsoft_oidc(monkeypatch, rsa_key_pair):
    """
    Serve discovery and JWKS from memory so no test touches the network.

    The signing key is returned directly; PyJWT still performs the full
    signature check against it, so the validation path under test is real.
    """
    _, public_key = rsa_key_pair

    monkeypatch.setattr(
        microsoft_provider,
        "get_openid_metadata",
        lambda tenant_id: {"issuer": f"https://login.microsoftonline.com/{tenant_id}/v2.0", "jwks_uri": JWKS_URI},
    )

    class _StubSigningKey:
        key = public_key

    class _StubJWKClient:
        def get_signing_key_from_jwt(self, token):
            return _StubSigningKey()

    monkeypatch.setattr(microsoft_provider, "get_jwk_client", lambda jwks_uri: _StubJWKClient())
    # Never let a stale cache leak between tests.
    microsoft_provider._discovery_cache.clear()
    microsoft_provider._jwk_clients.clear()


@pytest.fixture
def microsoft_configuration(monkeypatch):
    """Point get_configuration_value at an in-memory Microsoft configuration."""

    values = {
        "MICROSOFT_TENANT_ID": TENANT_ID,
        "MICROSOFT_CLIENT_ID": CLIENT_ID,
        "MICROSOFT_CLIENT_SECRET": CLIENT_SECRET,
    }

    def _apply(**overrides):
        merged = {**values, **overrides}

        def _fake_get_configuration_value(keys):
            return tuple(merged.get(key.get("key"), key.get("default")) for key in keys)

        monkeypatch.setattr(microsoft_provider, "get_configuration_value", _fake_get_configuration_value)
        return merged

    _apply()
    return _apply


class FakeRequest:
    """Minimal stand-in for the parts of HttpRequest the provider touches."""

    def __init__(self, host="plane.example.com", secure=True):
        self._host = host
        self._secure = secure
        self.session = {}
        self.META = {}

    def is_secure(self):
        return self._secure

    def get_host(self):
        return self._host


@pytest.fixture
def fake_request():
    return FakeRequest()


@pytest.fixture
def unique_email():
    def _email():
        return f"entra-{uuid.uuid4().hex[:12]}@example.com"

    return _email
