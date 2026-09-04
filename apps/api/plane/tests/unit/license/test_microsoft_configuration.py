# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
God Mode configuration behaviour for Microsoft Entra ID.

Covers who may read and write the settings, that the client secret is never
returned once stored, and that the provider cannot be enabled without a complete
and well-formed set of credentials.
"""

# Third party imports
import pytest
from rest_framework.test import APIClient

# Module imports
from plane.license.models import InstanceConfiguration
from plane.license.utils.encryption import decrypt_data
from plane.license.utils.masked_configuration import MASKED_SECRET_PLACEHOLDER

pytestmark = [pytest.mark.unit, pytest.mark.django_db]

CONFIGURATIONS_URL = "/api/instances/configurations/"
INSTANCE_URL = "/api/instances/"

TENANT_ID = "11111111-1111-4111-8111-111111111111"
CLIENT_ID = "33333333-3333-4333-8333-333333333333"


def _client(user=None):
    client = APIClient()
    if user:
        client.force_authenticate(user=user)
    return client


def _value_of(payload, key):
    return next((item["value"] for item in payload if item["key"] == key), None)


def _stored(key):
    row = InstanceConfiguration.objects.get(key=key)
    return decrypt_data(row.value) if row.is_encrypted else row.value


class TestAdministratorAuthorization:
    """Only instance-level (God Mode) administrators may touch this configuration."""

    def test_anonymous_user_cannot_read(self, instance, microsoft_configuration_rows):
        assert _client().get(CONFIGURATIONS_URL).status_code in (401, 403)

    def test_anonymous_user_cannot_write(self, instance, microsoft_configuration_rows):
        response = _client().patch(CONFIGURATIONS_URL, {"MICROSOFT_TENANT_ID": TENANT_ID}, format="json")
        assert response.status_code in (401, 403)
        assert _stored("MICROSOFT_TENANT_ID") == ""

    def test_ordinary_user_cannot_read(self, instance, ordinary_user, microsoft_configuration_rows):
        assert _client(ordinary_user).get(CONFIGURATIONS_URL).status_code == 403

    def test_ordinary_user_cannot_write(self, instance, ordinary_user, microsoft_configuration_rows):
        response = _client(ordinary_user).patch(
            CONFIGURATIONS_URL, {"MICROSOFT_TENANT_ID": TENANT_ID}, format="json"
        )
        assert response.status_code == 403
        assert _stored("MICROSOFT_TENANT_ID") == ""

    def test_workspace_admin_without_instance_rights_cannot_read(
        self, instance, workspace_admin_user, microsoft_configuration_rows
    ):
        """Being an admin of a workspace is not instance-level authority."""
        assert _client(workspace_admin_user).get(CONFIGURATIONS_URL).status_code == 403

    def test_workspace_admin_without_instance_rights_cannot_write(
        self, instance, workspace_admin_user, microsoft_configuration_rows
    ):
        response = _client(workspace_admin_user).patch(
            CONFIGURATIONS_URL, {"MICROSOFT_CLIENT_SECRET": "attacker-supplied"}, format="json"
        )
        assert response.status_code == 403
        assert _stored("MICROSOFT_CLIENT_SECRET") == ""

    def test_instance_admin_can_read(self, instance_admin_user, microsoft_configuration_rows):
        response = _client(instance_admin_user).get(CONFIGURATIONS_URL)
        assert response.status_code == 200
        assert _value_of(response.json(), "IS_MICROSOFT_ENABLED") == "0"

    def test_instance_admin_can_write(self, instance_admin_user, microsoft_configuration_rows):
        response = _client(instance_admin_user).patch(
            CONFIGURATIONS_URL, {"MICROSOFT_TENANT_ID": TENANT_ID}, format="json"
        )
        assert response.status_code == 200
        assert _stored("MICROSOFT_TENANT_ID") == TENANT_ID


class TestClientSecretIsWriteOnly:
    def test_stored_secret_is_never_returned(self, instance_admin_user, stored_secret):
        response = _client(instance_admin_user).get(CONFIGURATIONS_URL)

        assert response.status_code == 200
        assert _value_of(response.json(), "MICROSOFT_CLIENT_SECRET") == MASKED_SECRET_PLACEHOLDER
        # The real value must not appear anywhere in the payload.
        assert stored_secret not in response.content.decode()

    def test_unconfigured_secret_reads_as_empty(self, instance_admin_user, microsoft_configuration_rows):
        response = _client(instance_admin_user).get(CONFIGURATIONS_URL)
        assert _value_of(response.json(), "MICROSOFT_CLIENT_SECRET") == ""

    def test_patch_response_does_not_echo_the_secret(self, instance_admin_user, microsoft_configuration_rows):
        new_secret = "brand-new-client-secret"
        response = _client(instance_admin_user).patch(
            CONFIGURATIONS_URL, {"MICROSOFT_CLIENT_SECRET": new_secret}, format="json"
        )

        assert response.status_code == 200
        assert new_secret not in response.content.decode()
        assert _value_of(response.json(), "MICROSOFT_CLIENT_SECRET") == MASKED_SECRET_PLACEHOLDER

    def test_new_value_replaces_the_stored_secret(self, instance_admin_user, stored_secret):
        _client(instance_admin_user).patch(
            CONFIGURATIONS_URL, {"MICROSOFT_CLIENT_SECRET": "replacement-secret"}, format="json"
        )
        assert _stored("MICROSOFT_CLIENT_SECRET") == "replacement-secret"

    @pytest.mark.parametrize("submitted", ["", "   ", None, MASKED_SECRET_PLACEHOLDER])
    def test_blank_or_unchanged_submission_preserves_the_secret(
        self, instance_admin_user, stored_secret, submitted
    ):
        """Re-saving the form without retyping the secret must not wipe it."""
        response = _client(instance_admin_user).patch(
            CONFIGURATIONS_URL, {"MICROSOFT_CLIENT_SECRET": submitted}, format="json"
        )
        assert response.status_code == 200
        assert _stored("MICROSOFT_CLIENT_SECRET") == stored_secret

    def test_secret_is_encrypted_at_rest(self, instance_admin_user, microsoft_configuration_rows):
        _client(instance_admin_user).patch(
            CONFIGURATIONS_URL, {"MICROSOFT_CLIENT_SECRET": "another-secret"}, format="json"
        )
        row = InstanceConfiguration.objects.get(key="MICROSOFT_CLIENT_SECRET")
        assert row.is_encrypted is True
        assert row.value != "another-secret"
        assert decrypt_data(row.value) == "another-secret"

    def test_other_provider_secrets_keep_upstream_behaviour(self, instance_admin_user, db):
        """The masking is deliberately scoped to Microsoft only."""
        from plane.license.utils.encryption import encrypt_data

        InstanceConfiguration.objects.create(
            key="GOOGLE_CLIENT_SECRET",
            value=encrypt_data("google-secret"),
            category="GOOGLE",
            is_encrypted=True,
        )
        response = _client(instance_admin_user).get(CONFIGURATIONS_URL)
        assert _value_of(response.json(), "GOOGLE_CLIENT_SECRET") == "google-secret"


class TestEnableValidation:
    """Backend validation is mandatory; the frontend gate is not the control."""

    def _patch(self, user, payload):
        return _client(user).patch(CONFIGURATIONS_URL, payload, format="json")

    def test_cannot_enable_without_any_credentials(self, instance_admin_user, microsoft_configuration_rows):
        response = self._patch(instance_admin_user, {"IS_MICROSOFT_ENABLED": "1"})

        assert response.status_code == 400
        assert "error" in response.json()
        assert _stored("IS_MICROSOFT_ENABLED") == "0"

    @pytest.mark.parametrize("missing", ["MICROSOFT_TENANT_ID", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"])
    def test_cannot_enable_with_a_missing_credential(
        self, instance_admin_user, microsoft_configuration_rows, missing
    ):
        payload = {
            "IS_MICROSOFT_ENABLED": "1",
            "MICROSOFT_TENANT_ID": TENANT_ID,
            "MICROSOFT_CLIENT_ID": CLIENT_ID,
            "MICROSOFT_CLIENT_SECRET": "a-secret",
        }
        payload[missing] = ""

        response = self._patch(instance_admin_user, payload)
        assert response.status_code == 400
        assert missing in response.json()["error"]
        # Nothing at all is persisted on a rejected update.
        assert _stored("IS_MICROSOFT_ENABLED") == "0"
        assert _stored("MICROSOFT_TENANT_ID") == ""

    def test_can_enable_with_complete_credentials(self, instance_admin_user, microsoft_configuration_rows):
        response = self._patch(
            instance_admin_user,
            {
                "IS_MICROSOFT_ENABLED": "1",
                "MICROSOFT_TENANT_ID": TENANT_ID,
                "MICROSOFT_CLIENT_ID": CLIENT_ID,
                "MICROSOFT_CLIENT_SECRET": "a-secret",
            },
        )
        assert response.status_code == 200
        assert _stored("IS_MICROSOFT_ENABLED") == "1"

    def test_can_enable_when_the_secret_is_already_stored(self, instance_admin_user, stored_secret):
        """Enabling from the form does not require retyping the existing secret."""
        response = self._patch(
            instance_admin_user,
            {
                "IS_MICROSOFT_ENABLED": "1",
                "MICROSOFT_TENANT_ID": TENANT_ID,
                "MICROSOFT_CLIENT_ID": CLIENT_ID,
                "MICROSOFT_CLIENT_SECRET": MASKED_SECRET_PLACEHOLDER,
            },
        )
        assert response.status_code == 200
        assert _stored("IS_MICROSOFT_ENABLED") == "1"
        assert _stored("MICROSOFT_CLIENT_SECRET") == stored_secret

    def test_clearing_a_credential_while_enabled_is_rejected(self, instance_admin_user, stored_secret):
        self._patch(
            instance_admin_user,
            {
                "IS_MICROSOFT_ENABLED": "1",
                "MICROSOFT_TENANT_ID": TENANT_ID,
                "MICROSOFT_CLIENT_ID": CLIENT_ID,
            },
        )
        assert _stored("IS_MICROSOFT_ENABLED") == "1"

        response = self._patch(instance_admin_user, {"MICROSOFT_CLIENT_ID": ""})
        assert response.status_code == 400
        assert _stored("MICROSOFT_CLIENT_ID") == CLIENT_ID

    @pytest.mark.parametrize(
        "tenant_id",
        ["common", "organizations", "consumers", "https://login.microsoftonline.com/x", "not a tenant"],
    )
    def test_rejects_malformed_or_multi_tenant_ids(
        self, instance_admin_user, microsoft_configuration_rows, tenant_id
    ):
        response = self._patch(
            instance_admin_user,
            {
                "IS_MICROSOFT_ENABLED": "1",
                "MICROSOFT_TENANT_ID": tenant_id,
                "MICROSOFT_CLIENT_ID": CLIENT_ID,
                "MICROSOFT_CLIENT_SECRET": "a-secret",
            },
        )
        assert response.status_code == 400
        assert "MICROSOFT_TENANT_ID" in response.json()["error"]
        assert _stored("IS_MICROSOFT_ENABLED") == "0"

    def test_disabling_is_always_allowed(self, instance_admin_user, stored_secret):
        response = self._patch(instance_admin_user, {"IS_MICROSOFT_ENABLED": "0"})
        assert response.status_code == 200
        assert _stored("IS_MICROSOFT_ENABLED") == "0"

    def test_saving_credentials_while_disabled_is_allowed(
        self, instance_admin_user, microsoft_configuration_rows
    ):
        """Administrators can fill the form in before turning the provider on."""
        response = self._patch(instance_admin_user, {"MICROSOFT_TENANT_ID": TENANT_ID})
        assert response.status_code == 200
        assert _stored("MICROSOFT_TENANT_ID") == TENANT_ID

    def test_unrelated_providers_are_untouched_by_the_validation(
        self, instance_admin_user, microsoft_configuration_rows, db
    ):
        InstanceConfiguration.objects.create(
            key="IS_GOOGLE_ENABLED", value="0", category="GOOGLE", is_encrypted=False
        )
        InstanceConfiguration.objects.create(
            key="GOOGLE_CLIENT_ID", value="", category="GOOGLE", is_encrypted=False
        )
        # Upstream allows this; the new validation must not start blocking it.
        response = self._patch(instance_admin_user, {"IS_GOOGLE_ENABLED": "1"})
        assert response.status_code == 200
        assert _stored("IS_GOOGLE_ENABLED") == "1"


class TestPublicInstanceEndpoint:
    """The unauthenticated endpoint exposes availability, never configuration."""

    def test_exposes_only_the_enabled_boolean(self, instance, microsoft_configuration_rows):
        response = _client().get(INSTANCE_URL)

        assert response.status_code == 200
        config = response.json()["config"]
        assert config["is_microsoft_enabled"] is False
        for key in ("microsoft_tenant_id", "microsoft_client_id", "microsoft_client_secret"):
            assert key not in config

    def test_reflects_the_enabled_flag(self, instance, microsoft_configuration_rows):
        InstanceConfiguration.objects.filter(key="IS_MICROSOFT_ENABLED").update(value="1")
        config = _client().get(INSTANCE_URL).json()["config"]
        assert config["is_microsoft_enabled"] is True

    def test_never_leaks_credentials(self, instance, stored_secret):
        InstanceConfiguration.objects.filter(key="MICROSOFT_TENANT_ID").update(value=TENANT_ID)
        InstanceConfiguration.objects.filter(key="MICROSOFT_CLIENT_ID").update(value=CLIENT_ID)
        InstanceConfiguration.objects.filter(key="IS_MICROSOFT_ENABLED").update(value="1")

        body = _client().get(INSTANCE_URL).content.decode()

        assert stored_secret not in body
        assert TENANT_ID not in body
        assert CLIENT_ID not in body
        assert "login.microsoftonline.com" not in body

    def test_existing_provider_flags_are_unchanged(self, instance, microsoft_configuration_rows):
        config = _client().get(INSTANCE_URL).json()["config"]
        for key in (
            "is_google_enabled",
            "is_github_enabled",
            "is_gitlab_enabled",
            "is_gitea_enabled",
            "is_magic_login_enabled",
            "is_email_password_enabled",
        ):
            assert key in config


class TestConfigurationSeeding:
    def test_microsoft_keys_are_registered_with_safe_defaults(self):
        """New installs and upgrades both start with the provider off."""
        from plane.utils.instance_config_variables import instance_config_variables

        registered = {item["key"]: item for item in instance_config_variables}

        for key in (
            "IS_MICROSOFT_ENABLED",
            "MICROSOFT_TENANT_ID",
            "MICROSOFT_CLIENT_ID",
            "MICROSOFT_CLIENT_SECRET",
            "ENABLE_MICROSOFT_SYNC",
        ):
            assert key in registered
            assert registered[key]["category"] == "MICROSOFT"

        assert registered["IS_MICROSOFT_ENABLED"]["value"] == "0"
        assert registered["ENABLE_MICROSOFT_SYNC"]["value"] == "0"
        # Only the secret is encrypted at rest.
        assert registered["MICROSOFT_CLIENT_SECRET"]["is_encrypted"] is True
        assert registered["MICROSOFT_CLIENT_ID"]["is_encrypted"] is False
        assert registered["MICROSOFT_TENANT_ID"]["is_encrypted"] is False
