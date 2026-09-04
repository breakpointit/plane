# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Unit tests for the Microsoft Entra ID OAuth/OIDC provider."""

# Python imports
import time
from urllib.parse import parse_qs, urlparse

# Third party imports
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

# Module imports
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)
from plane.authentication.provider.oauth.microsoft import (
    MicrosoftOAuthProvider,
    generate_code_challenge,
    generate_code_verifier,
    generate_nonce,
    tenant_guid_from_issuer,
    validate_tenant_id,
)

from .conftest import CLIENT_ID, ISSUER, OBJECT_ID, OTHER_TENANT_ID, TENANT_ID

pytestmark = pytest.mark.unit


class TestTenantIdValidation:
    """MICROSOFT_TENANT_ID is an identifier, never a URL. It is the SSRF boundary."""

    @pytest.mark.parametrize(
        "tenant_id",
        [
            TENANT_ID,
            TENANT_ID.upper(),
            "contoso.onmicrosoft.com",
            "example.com",
            f"  {TENANT_ID}  ",
        ],
    )
    def test_accepts_guid_and_verified_domain(self, tenant_id):
        assert validate_tenant_id(tenant_id) == tenant_id.strip().lower()

    @pytest.mark.parametrize("tenant_id", ["common", "organizations", "consumers", "COMMON", "Organizations"])
    def test_rejects_multi_tenant_aliases(self, tenant_id):
        """This integration is single tenant; shared endpoints defeat the tid check."""
        with pytest.raises(AuthenticationException) as exc:
            validate_tenant_id(tenant_id)
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["MICROSOFT_NOT_CONFIGURED"]

    def test_rejects_microsoft_account_tenant(self):
        with pytest.raises(AuthenticationException):
            validate_tenant_id("9188040d-6c67-4c5b-b112-36a304b66dad")

    @pytest.mark.parametrize(
        "tenant_id",
        [
            "",
            None,
            "   ",
            "https://login.microsoftonline.com/tenant",
            "http://evil.example.com",
            "//evil.example.com",
            "tenant/../../etc/passwd",
            "tenant?x=1",
            "user@example.com",
            # A bare IP is not a verified domain; the final label must be alphabetic.
            "169.254.169.254",
            "127.0.0.1",
            "localhost",
            "not a tenant",
            "tenant\nid",
            12345,
        ],
    )
    def test_rejects_urls_and_junk(self, tenant_id):
        """Anything that could steer a request elsewhere must be refused."""
        with pytest.raises(AuthenticationException) as exc:
            validate_tenant_id(tenant_id)
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["MICROSOFT_NOT_CONFIGURED"]

    def test_tenant_guid_from_issuer(self):
        assert tenant_guid_from_issuer(ISSUER) == TENANT_ID
        assert tenant_guid_from_issuer("https://login.microsoftonline.com/not-a-guid/v2.0") is None
        assert tenant_guid_from_issuer("https://login.microsoftonline.com/") is None


class TestPkceHelpers:
    def test_code_challenge_is_s256_and_url_safe(self):
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)

        # RFC 7636 length bounds for the verifier.
        assert 43 <= len(verifier) <= 128
        # Base64url, unpadded.
        assert "=" not in challenge
        assert "+" not in challenge and "/" not in challenge
        # Deterministic for a given verifier, and distinct from it.
        assert generate_code_challenge(verifier) == challenge
        assert challenge != verifier

    def test_verifier_and_nonce_are_unpredictable(self):
        assert len({generate_code_verifier() for _ in range(50)}) == 50
        assert len({generate_nonce() for _ in range(50)}) == 50


class TestAuthorizationUrl:
    def _provider(self, request, **kwargs):
        return MicrosoftOAuthProvider(request=request, **kwargs)

    def test_authorization_url_uses_configured_tenant_and_client(self, microsoft_configuration, fake_request):
        verifier = generate_code_verifier()
        provider = self._provider(
            fake_request,
            state="state-value",
            nonce="nonce-value",
            code_challenge=generate_code_challenge(verifier),
        )
        url = urlparse(provider.get_auth_url())
        params = {k: v[0] for k, v in parse_qs(url.query).items()}

        assert url.scheme == "https"
        assert url.netloc == "login.microsoftonline.com"
        # Microsoft identity platform v2, scoped to the configured tenant.
        assert url.path == f"/{TENANT_ID}/oauth2/v2.0/authorize"
        assert params["client_id"] == CLIENT_ID
        assert params["response_type"] == "code"
        assert params["response_mode"] == "query"
        assert params["redirect_uri"] == "https://plane.example.com/auth/microsoft/callback/"
        assert params["state"] == "state-value"
        assert params["nonce"] == "nonce-value"

    def test_requests_only_minimal_oidc_scopes(self, microsoft_configuration, fake_request):
        provider = self._provider(fake_request, state="s")
        params = {k: v[0] for k, v in parse_qs(urlparse(provider.get_auth_url()).query).items()}

        assert set(params["scope"].split()) == {"openid", "profile", "email"}
        # No Microsoft Graph permission, and no refresh token is requested.
        assert "User.Read" not in params["scope"]
        assert "offline_access" not in params["scope"]

    def test_uses_s256_pkce_never_plain(self, microsoft_configuration, fake_request):
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        provider = self._provider(fake_request, state="s", code_challenge=challenge)
        params = {k: v[0] for k, v in parse_qs(urlparse(provider.get_auth_url()).query).items()}

        assert params["code_challenge"] == challenge
        assert params["code_challenge_method"] == "S256"
        assert params["code_challenge_method"] != "plain"

    def test_token_endpoint_is_tenant_scoped(self, microsoft_configuration, fake_request):
        provider = self._provider(fake_request, state="s")
        assert provider.get_token_url() == f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

    def test_domain_tenant_is_used_verbatim_in_endpoints(self, microsoft_configuration, fake_request):
        microsoft_configuration(MICROSOFT_TENANT_ID="contoso.onmicrosoft.com")
        provider = self._provider(fake_request, state="s")
        assert urlparse(provider.get_auth_url()).path == "/contoso.onmicrosoft.com/oauth2/v2.0/authorize"

    @pytest.mark.parametrize(
        "missing",
        ["MICROSOFT_TENANT_ID", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"],
    )
    def test_incomplete_configuration_fails_closed(self, microsoft_configuration, fake_request, missing):
        microsoft_configuration(**{missing: ""})
        with pytest.raises(AuthenticationException) as exc:
            self._provider(fake_request, state="s")
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["MICROSOFT_NOT_CONFIGURED"]

    def test_malformed_tenant_is_rejected_before_building_a_url(self, microsoft_configuration, fake_request):
        microsoft_configuration(MICROSOFT_TENANT_ID="https://attacker.example.com")
        with pytest.raises(AuthenticationException) as exc:
            self._provider(fake_request, state="s")
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["MICROSOFT_NOT_CONFIGURED"]


class TestIdTokenValidation:
    """The ID token is the only source of identity, so it is verified in full."""

    def _provider(self, microsoft_configuration, fake_request, nonce=None):
        return MicrosoftOAuthProvider(request=fake_request, code="auth-code", nonce=nonce)

    def _validate(self, microsoft_configuration, fake_request, token, nonce=None):
        provider = self._provider(microsoft_configuration, fake_request, nonce=nonce)
        return provider._validate_id_token(token)

    def test_valid_token_is_accepted(
        self, microsoft_configuration, fake_request, sign_id_token, id_token_claims
    ):
        claims = self._validate(microsoft_configuration, fake_request, sign_id_token(id_token_claims()))
        assert claims["tid"] == TENANT_ID
        assert claims["aud"] == CLIENT_ID

    def test_rejects_token_signed_by_an_unknown_key(
        self, microsoft_configuration, fake_request, sign_id_token, id_token_claims
    ):
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = sign_id_token(id_token_claims(), key=attacker_key)
        with pytest.raises(AuthenticationException) as exc:
            self._validate(microsoft_configuration, fake_request, token)
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["MICROSOFT_OAUTH_PROVIDER_ERROR"]

    def test_rejects_unsigned_token(self, microsoft_configuration, fake_request, id_token_claims):
        import jwt as pyjwt

        token = pyjwt.encode(id_token_claims(), key="", algorithm="none")
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    def test_rejects_wrong_audience(
        self, microsoft_configuration, fake_request, sign_id_token, id_token_claims
    ):
        token = sign_id_token(id_token_claims(aud="00000000-0000-4000-8000-000000000999"))
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    def test_rejects_wrong_issuer(self, microsoft_configuration, fake_request, sign_id_token, id_token_claims):
        token = sign_id_token(id_token_claims(iss=f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0"))
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    def test_rejects_foreign_tenant(self, microsoft_configuration, fake_request, sign_id_token, id_token_claims):
        """A valid token from another directory must not grant access here."""
        token = sign_id_token(id_token_claims(tid=OTHER_TENANT_ID))
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    def test_rejects_missing_tid(self, microsoft_configuration, fake_request, sign_id_token, id_token_claims):
        token = sign_id_token(id_token_claims(tid=None))
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    def test_rejects_expired_token(self, microsoft_configuration, fake_request, sign_id_token, id_token_claims):
        now = int(time.time())
        token = sign_id_token(id_token_claims(iat=now - 7200, nbf=now - 7200, exp=now - 3600))
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    def test_rejects_token_not_yet_valid(
        self, microsoft_configuration, fake_request, sign_id_token, id_token_claims
    ):
        now = int(time.time())
        token = sign_id_token(id_token_claims(nbf=now + 3600, exp=now + 7200))
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    @pytest.mark.parametrize("required", ["exp", "iat", "aud", "iss", "sub"])
    def test_rejects_token_missing_required_claims(
        self, microsoft_configuration, fake_request, sign_id_token, id_token_claims, required
    ):
        token = sign_id_token(id_token_claims(**{required: None}))
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token)

    def test_rejects_malformed_token(self, microsoft_configuration, fake_request):
        for token in ("", "not-a-jwt", "a.b.c", "eyJhbGciOiJSUzI1NiJ9.garbage"):
            with pytest.raises(AuthenticationException):
                self._validate(microsoft_configuration, fake_request, token)

    def test_nonce_must_match_when_one_was_issued(
        self, microsoft_configuration, fake_request, sign_id_token, id_token_claims
    ):
        token = sign_id_token(id_token_claims(nonce="issued-nonce"))
        # Matching nonce passes.
        assert self._validate(microsoft_configuration, fake_request, token, nonce="issued-nonce")

        # A different nonce, or none at all in the token, must fail.
        with pytest.raises(AuthenticationException):
            self._validate(microsoft_configuration, fake_request, token, nonce="different-nonce")
        with pytest.raises(AuthenticationException):
            self._validate(
                microsoft_configuration,
                fake_request,
                sign_id_token(id_token_claims()),
                nonce="issued-nonce",
            )


class TestUserIdentity:
    def _provider_with_claims(self, fake_request, claims, nonce=None):
        provider = MicrosoftOAuthProvider(request=fake_request, code="auth-code", nonce=nonce)
        provider.id_token_claims = claims
        return provider

    def test_identity_is_tenant_plus_object_id_not_email(
        self, microsoft_configuration, fake_request, id_token_claims
    ):
        provider = self._provider_with_claims(fake_request, id_token_claims())
        provider.set_user_data()

        user = provider.user_data["user"]
        assert user["provider_id"] == f"{TENANT_ID}.{OBJECT_ID}"
        # The stable identifier must not be the (mutable) email address.
        assert provider.user_data["email"] not in user["provider_id"]
        assert user["first_name"] == "Entra"
        assert user["last_name"] == "User"
        assert user["is_password_autoset"] is True

    def test_falls_back_to_sub_when_oid_is_absent(
        self, microsoft_configuration, fake_request, id_token_claims
    ):
        provider = self._provider_with_claims(fake_request, id_token_claims(oid=None))
        provider.set_user_data()
        assert provider.user_data["user"]["provider_id"] == f"{TENANT_ID}.subject-identifier"

    @pytest.mark.parametrize("email", [None, "", "   "])
    def test_missing_email_fails_closed(self, microsoft_configuration, fake_request, id_token_claims, email):
        """No email means no login — never a fabricated address."""
        provider = self._provider_with_claims(fake_request, id_token_claims(email=email))
        with pytest.raises(AuthenticationException) as exc:
            provider.set_user_data()
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["MICROSOFT_OAUTH_PROVIDER_ERROR"]

    def test_preferred_username_is_not_used_as_an_email(
        self, microsoft_configuration, fake_request, id_token_claims
    ):
        """preferred_username carries no verification guarantee, so it is ignored."""
        claims = id_token_claims(email=None)
        claims["preferred_username"] = "someone.else@example.com"
        provider = self._provider_with_claims(fake_request, claims)
        with pytest.raises(AuthenticationException):
            provider.set_user_data()

    def test_missing_identity_claims_fail_closed(
        self, microsoft_configuration, fake_request, id_token_claims
    ):
        provider = self._provider_with_claims(fake_request, id_token_claims(oid=None, sub=None))
        with pytest.raises(AuthenticationException):
            provider.set_user_data()

    def test_set_user_data_requires_validated_claims(self, microsoft_configuration, fake_request):
        provider = MicrosoftOAuthProvider(request=fake_request, code="auth-code")
        with pytest.raises(AuthenticationException):
            provider.set_user_data()


class TestTokenHandling:
    def test_microsoft_credentials_are_not_persisted(
        self, microsoft_configuration, fake_request, sign_id_token, id_token_claims, monkeypatch
    ):
        """Plane only needs to identify the user; no Microsoft token is stored."""
        provider = MicrosoftOAuthProvider(
            request=fake_request, code="auth-code", nonce="n", code_verifier="verifier"
        )

        captured = {}

        def _fake_get_user_token(data, headers=None):
            captured.update(data)
            return {
                "access_token": "ms-access-token",
                "refresh_token": "ms-refresh-token",
                "id_token": sign_id_token(id_token_claims(nonce="n")),
                "expires_in": 3600,
            }

        monkeypatch.setattr(provider, "get_user_token", _fake_get_user_token)
        provider.set_token_data()

        # PKCE verifier and the client secret go up ...
        assert captured["code_verifier"] == "verifier"
        assert captured["grant_type"] == "authorization_code"
        assert captured["redirect_uri"] == "https://plane.example.com/auth/microsoft/callback/"
        # ... but nothing from the response is retained.
        assert provider.token_data["access_token"] == ""
        assert provider.token_data["refresh_token"] is None
        assert provider.token_data["id_token"] == ""

    def test_token_response_without_id_token_fails(
        self, microsoft_configuration, fake_request, monkeypatch
    ):
        provider = MicrosoftOAuthProvider(request=fake_request, code="auth-code")
        monkeypatch.setattr(provider, "get_user_token", lambda data, headers=None: {"access_token": "x"})
        with pytest.raises(AuthenticationException) as exc:
            provider.set_token_data()
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["MICROSOFT_OAUTH_PROVIDER_ERROR"]

    def test_provider_error_code_mapping(self, microsoft_configuration, fake_request):
        provider = MicrosoftOAuthProvider(request=fake_request, code="auth-code")
        assert provider.authentication_error_code() == "MICROSOFT_OAUTH_PROVIDER_ERROR"
        assert provider.provider == "microsoft"
