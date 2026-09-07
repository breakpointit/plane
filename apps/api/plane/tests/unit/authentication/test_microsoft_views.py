# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
End-to-end tests for the Microsoft Entra ID initiation and callback endpoints.

The Microsoft side is stubbed (discovery and JWKS come from the package conftest;
the token endpoint is patched per test), so these exercise Plane's own state,
nonce, PKCE, session and account-provisioning behaviour without any network call.
"""

# Python imports
import time
from urllib.parse import parse_qs, urlparse

# Third party imports
import pytest
from django.utils import timezone

# Module imports
from plane.authentication.provider.oauth import microsoft as microsoft_provider
from plane.db.models import Account, User
from plane.license.models import Instance

from .conftest import CLIENT_ID, OBJECT_ID, TENANT_ID

pytestmark = [pytest.mark.unit, pytest.mark.django_db]

INITIATE_URL = "/auth/microsoft/"
CALLBACK_URL = "/auth/microsoft/callback/"
SPACE_INITIATE_URL = "/auth/spaces/microsoft/"
SPACE_CALLBACK_URL = "/auth/spaces/microsoft/callback/"


@pytest.fixture
def configured_instance(db):
    """A set-up instance, which every OAuth initiation requires."""
    return Instance.objects.create(
        instance_name="Test Instance",
        instance_id="test-instance",
        current_version="1.0.0",
        latest_version="1.0.0",
        last_checked_at=timezone.now(),
        is_setup_done=True,
    )


@pytest.fixture
def db_microsoft_configuration(monkeypatch):
    """Configure Microsoft credentials for code paths that read them from the DB."""
    values = {
        "MICROSOFT_TENANT_ID": TENANT_ID,
        "MICROSOFT_CLIENT_ID": CLIENT_ID,
        "MICROSOFT_CLIENT_SECRET": "test-client-secret-not-a-real-value",
        "IS_MICROSOFT_ENABLED": "1",
        "ENABLE_SIGNUP": "1",
        "ENABLE_MICROSOFT_SYNC": "0",
    }

    def _apply(**overrides):
        merged = {**values, **overrides}

        def _fake(keys):
            return tuple(merged.get(key.get("key"), key.get("default")) for key in keys)

        # The provider and the shared adapter each import the helper by name.
        monkeypatch.setattr(microsoft_provider, "get_configuration_value", _fake)
        monkeypatch.setattr("plane.authentication.adapter.base.get_configuration_value", _fake)
        return merged

    _apply()
    return _apply


def _stub_token_endpoint(monkeypatch, id_token, extra=None):
    """Make the provider's token exchange return a fixed response."""
    payload = {"access_token": "ms-access-token", "id_token": id_token, "expires_in": 3600}
    payload.update(extra or {})
    monkeypatch.setattr(
        microsoft_provider.MicrosoftOAuthProvider,
        "get_user_token",
        lambda self, data, headers=None: payload,
    )


def _start_flow(client, url=INITIATE_URL):
    """Run the initiation endpoint and return (response, session values)."""
    response = client.get(url)
    session = client.session
    return response, {
        "state": session.get("state"),
        "nonce": session.get("microsoft_nonce"),
        "code_verifier": session.get("microsoft_code_verifier"),
        "issued_at": session.get("microsoft_state_issued_at"),
    }


class TestInitiation:
    def test_redirects_to_configured_tenant(
        self, client, configured_instance, db_microsoft_configuration
    ):
        response, session = _start_flow(client)

        assert response.status_code == 302
        target = urlparse(response.url)
        assert target.netloc == "login.microsoftonline.com"
        assert target.path == f"/{TENANT_ID}/oauth2/v2.0/authorize"

        params = {k: v[0] for k, v in parse_qs(target.query).items()}
        assert params["client_id"] == CLIENT_ID
        assert params["redirect_uri"].endswith("/auth/microsoft/callback/")
        assert set(params["scope"].split()) == {"openid", "profile", "email"}
        assert params["code_challenge_method"] == "S256"

        # State, nonce and verifier are all created and held server-side.
        assert params["state"] == session["state"]
        assert params["nonce"] == session["nonce"]
        assert session["code_verifier"]
        assert params["code_challenge"] != session["code_verifier"]
        assert isinstance(session["issued_at"], int)

    def test_state_and_nonce_differ_between_attempts(
        self, client, configured_instance, db_microsoft_configuration
    ):
        _, first = _start_flow(client)
        _, second = _start_flow(client)
        assert first["state"] != second["state"]
        assert first["nonce"] != second["nonce"]
        assert first["code_verifier"] != second["code_verifier"]

    def test_unconfigured_provider_does_not_reach_microsoft(
        self, client, configured_instance, db_microsoft_configuration
    ):
        """Behaves like any other disabled/unconfigured provider: a local error redirect."""
        db_microsoft_configuration(MICROSOFT_CLIENT_SECRET="")
        response = client.get(INITIATE_URL)

        assert response.status_code == 302
        assert "login.microsoftonline.com" not in response.url
        assert "error_code=5113" in response.url
        assert client.session.get("state") is None

    def test_no_instance_fails_closed(self, client, db, db_microsoft_configuration):
        response = client.get(INITIATE_URL)
        assert response.status_code == 302
        assert "login.microsoftonline.com" not in response.url
        assert "error_code=5000" in response.url

    def test_disabled_provider_refuses_even_by_direct_url(
        self, client, configured_instance, db_microsoft_configuration
    ):
        """
        Turning the God Mode toggle off must actually disable the endpoint, not
        merely hide the login button. Credentials stay configured here, so only
        the flag is doing the work.
        """
        db_microsoft_configuration(IS_MICROSOFT_ENABLED="0")
        response = client.get(INITIATE_URL)

        assert response.status_code == 302
        assert "login.microsoftonline.com" not in response.url
        assert "error_code=5113" in response.url
        assert client.session.get("state") is None

    def test_disabled_provider_refuses_the_callback_too(
        self, client, configured_instance, db_microsoft_configuration, sign_id_token, id_token_claims, monkeypatch
    ):
        """Disabling mid-flow must stop an in-flight authorization completing."""
        _, session = _start_flow(client)
        _stub_token_endpoint(monkeypatch, sign_id_token(id_token_claims(nonce=session["nonce"])))
        db_microsoft_configuration(IS_MICROSOFT_ENABLED="0")

        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})
        assert "error_code=5113" in response.url
        assert not User.objects.exists()

    def test_initiate_is_not_rate_limited(self, client, configured_instance, db_microsoft_configuration):
        """
        Parity with Google/GitHub/GitLab/Gitea: the initiation endpoint validates
        no credentials and only redirects to Microsoft, so it carries no throttle.
        A shared per-IP limit here would break sign-in for everyone behind one
        corporate egress IP.
        """
        for _ in range(15):
            response = client.get(INITIATE_URL)
            assert "error_code=5900" not in response.url
        assert "login.microsoftonline.com" in response.url

    def test_space_initiation_also_redirects_to_the_tenant(
        self, client, configured_instance, db_microsoft_configuration
    ):
        response, session = _start_flow(client, SPACE_INITIATE_URL)
        assert response.status_code == 302
        assert urlparse(response.url).path == f"/{TENANT_ID}/oauth2/v2.0/authorize"
        assert session["state"] and session["nonce"] and session["code_verifier"]


class TestCallbackStateValidation:
    """State/nonce/verifier are single-use and must fail closed."""

    def test_valid_callback_signs_the_user_in(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        _, session = _start_flow(client)
        _stub_token_endpoint(monkeypatch, sign_id_token(id_token_claims(nonce=session["nonce"])))

        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})

        assert response.status_code == 302
        assert "error_code" not in response.url
        assert User.objects.filter(email="entra.user@example.com").exists()

    def test_missing_state_fails(
        self, client, configured_instance, db_microsoft_configuration
    ):
        _start_flow(client)
        response = client.get(CALLBACK_URL, {"code": "auth-code"})
        assert "error_code=5114" in response.url
        assert not User.objects.exists()

    def test_mismatched_state_fails(
        self, client, configured_instance, db_microsoft_configuration
    ):
        _start_flow(client)
        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": "attacker-supplied-state"})
        assert "error_code=5114" in response.url
        assert not User.objects.exists()

    def test_callback_without_an_initiation_fails(self, client, configured_instance, db_microsoft_configuration):
        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": "some-state"})
        assert "error_code=5114" in response.url

    def test_expired_state_fails(
        self, client, configured_instance, db_microsoft_configuration, monkeypatch
    ):
        _, session = _start_flow(client)

        # Age the stored state past its TTL.
        django_session = client.session
        django_session["microsoft_state_issued_at"] = int(time.time()) - (11 * 60)
        django_session.save()

        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})
        assert "error_code=5114" in response.url
        assert not User.objects.exists()

    def test_missing_code_fails(self, client, configured_instance, db_microsoft_configuration):
        _, session = _start_flow(client)
        response = client.get(CALLBACK_URL, {"state": session["state"]})
        assert "error_code=5114" in response.url

    def test_state_is_single_use(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        """Replaying a callback must not work, even with a previously valid state."""
        _, session = _start_flow(client)
        _stub_token_endpoint(monkeypatch, sign_id_token(id_token_claims(nonce=session["nonce"])))

        first = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})
        assert "error_code" not in first.url

        replay = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})
        assert "error_code=5114" in replay.url

    def test_session_values_are_cleared_after_a_failure(
        self, client, configured_instance, db_microsoft_configuration
    ):
        _start_flow(client)
        client.get(CALLBACK_URL, {"code": "auth-code", "state": "wrong"})
        session = client.session
        assert session.get("state") is None
        assert session.get("microsoft_nonce") is None
        assert session.get("microsoft_code_verifier") is None


class TestCallbackTokenValidation:
    def _flow(self, client):
        _, session = _start_flow(client)
        return session

    def test_token_exchange_failure_fails_closed(
        self, client, configured_instance, db_microsoft_configuration, monkeypatch
    ):
        session = self._flow(client)

        def _raise(self, data, headers=None):
            raise microsoft_provider.AuthenticationException(
                error_code=microsoft_provider.AUTHENTICATION_ERROR_CODES["MICROSOFT_OAUTH_PROVIDER_ERROR"],
                error_message="MICROSOFT_OAUTH_PROVIDER_ERROR",
            )

        monkeypatch.setattr(microsoft_provider.MicrosoftOAuthProvider, "get_user_token", _raise)
        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})

        assert "error_code=5114" in response.url
        assert not User.objects.exists()

    def test_nonce_replay_is_rejected(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        session = self._flow(client)
        # A token minted for a different authentication attempt.
        _stub_token_endpoint(monkeypatch, sign_id_token(id_token_claims(nonce="a-different-nonce")))

        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})
        assert "error_code=5114" in response.url
        assert not User.objects.exists()

    def test_foreign_tenant_token_is_rejected(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        session = self._flow(client)
        _stub_token_endpoint(
            monkeypatch,
            sign_id_token(id_token_claims(nonce=session["nonce"], tid="22222222-2222-4222-8222-222222222222")),
        )
        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})
        assert "error_code=5114" in response.url
        assert not User.objects.exists()

    def test_missing_email_claim_does_not_create_a_user(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        session = self._flow(client)
        _stub_token_endpoint(monkeypatch, sign_id_token(id_token_claims(nonce=session["nonce"], email=None)))

        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})
        assert "error_code=5114" in response.url
        assert not User.objects.exists()

    def test_error_redirect_leaks_no_credentials(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        """The browser-visible error must carry only a code and a generic message."""
        session = self._flow(client)
        id_token = sign_id_token(id_token_claims(nonce="wrong"))
        _stub_token_endpoint(monkeypatch, id_token)

        response = client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})

        for secret in ("test-client-secret-not-a-real-value", "ms-access-token", id_token, "auth-code"):
            assert secret not in response.url


class TestAccountProvisioning:
    def _authenticate(self, client, sign_id_token, id_token_claims, monkeypatch, **claim_overrides):
        _, session = _start_flow(client)
        _stub_token_endpoint(
            monkeypatch, sign_id_token(id_token_claims(nonce=session["nonce"], **claim_overrides))
        )
        return client.get(CALLBACK_URL, {"code": "auth-code", "state": session["state"]})

    def test_new_user_is_created_with_a_microsoft_account_record(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        self._authenticate(client, sign_id_token, id_token_claims, monkeypatch)

        user = User.objects.get(email="entra.user@example.com")
        assert user.is_active
        assert user.last_login_medium == "microsoft"

        account = Account.objects.get(user=user, provider="microsoft")
        # Stable identity: tenant + object id, not the email address.
        assert account.provider_account_id == f"{TENANT_ID}.{OBJECT_ID}"
        # No Microsoft credential is retained.
        assert account.access_token == ""
        assert account.refresh_token is None
        assert account.id_token == ""

    def test_returning_user_logs_into_the_same_account(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        self._authenticate(client, sign_id_token, id_token_claims, monkeypatch)
        user_id = User.objects.get(email="entra.user@example.com").id

        client.logout()
        self._authenticate(client, sign_id_token, id_token_claims, monkeypatch)

        assert User.objects.filter(email="entra.user@example.com").count() == 1
        assert User.objects.get(email="entra.user@example.com").id == user_id
        assert Account.objects.filter(provider="microsoft").count() == 1

    def test_signup_disabled_blocks_unknown_users(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        """Provisioning still runs through Plane's existing signup gate."""
        db_microsoft_configuration(ENABLE_SIGNUP="0")
        response = self._authenticate(client, sign_id_token, id_token_claims, monkeypatch)

        assert "error_code=5015" in response.url
        assert not User.objects.filter(email="entra.user@example.com").exists()

    def test_email_alone_cannot_claim_an_account_without_a_valid_tenant_token(
        self,
        client,
        configured_instance,
        db_microsoft_configuration,
        sign_id_token,
        id_token_claims,
        monkeypatch,
    ):
        """
        An identity from another Entra tenant asserting the same email address must
        not reach the account-association step at all.
        """
        existing = User.objects.create(email="entra.user@example.com", username="existing")

        response = self._authenticate(
            client,
            sign_id_token,
            id_token_claims,
            monkeypatch,
            tid="22222222-2222-4222-8222-222222222222",
        )

        assert "error_code=5114" in response.url
        assert not Account.objects.filter(user=existing, provider="microsoft").exists()
