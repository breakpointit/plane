# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Third party imports
import pytest
from django.core.cache import cache
from django.utils import timezone

# Module imports
from plane.license.models import Instance, InstanceAdmin, InstanceConfiguration


@pytest.fixture(autouse=True)
def local_cache(settings):
    """
    Run these tests against an in-process cache.

    The instance endpoints wrap their GETs in `cache_response`, which calls
    `cache.get` unconditionally. Using locmem keeps the tests independent of a
    running Redis/Valkey and stops responses leaking between tests.
    """
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def instance(db):
    return Instance.objects.create(
        instance_name="Test Instance",
        instance_id="test-instance",
        current_version="1.0.0",
        latest_version="1.0.0",
        last_checked_at=timezone.now(),
        is_setup_done=True,
    )


@pytest.fixture
def instance_admin_user(db, instance, django_user_model):
    """A God Mode administrator (instance-level, role >= 15)."""
    user = django_user_model.objects.create(email="god-mode@example.com", username="god-mode")
    InstanceAdmin.objects.create(instance=instance, user=user, role=20)
    return user


@pytest.fixture
def ordinary_user(db, django_user_model):
    """An authenticated user with no instance-level role at all."""
    return django_user_model.objects.create(email="member@example.com", username="member")


@pytest.fixture
def workspace_admin_user(db, django_user_model):
    """
    A workspace admin who is *not* an instance administrator.

    Workspace-level authority must not grant access to instance configuration.
    """
    from plane.db.models import Workspace, WorkspaceMember

    user = django_user_model.objects.create(email="workspace-admin@example.com", username="workspace-admin")
    workspace = Workspace.objects.create(name="Test Workspace", slug="test-workspace", owner=user)
    WorkspaceMember.objects.create(workspace=workspace, member=user, role=20)
    return user


@pytest.fixture
def microsoft_configuration_rows(db):
    """Seed the Microsoft configuration rows the way `configure_instance` would."""
    from plane.license.utils.encryption import encrypt_data

    rows = {}
    for key, value, encrypted in (
        ("IS_MICROSOFT_ENABLED", "0", False),
        ("MICROSOFT_TENANT_ID", "", False),
        ("MICROSOFT_CLIENT_ID", "", False),
        ("MICROSOFT_CLIENT_SECRET", "", True),
        ("ENABLE_MICROSOFT_SYNC", "0", False),
    ):
        rows[key] = InstanceConfiguration.objects.create(
            key=key,
            value=encrypt_data(value) if encrypted and value else value,
            category="MICROSOFT",
            is_encrypted=encrypted,
        )
    return rows


@pytest.fixture
def stored_secret(db, microsoft_configuration_rows):
    """Put a known client secret in place, encrypted, and return the plaintext."""
    from plane.license.utils.encryption import encrypt_data

    secret = "stored-client-secret-not-a-real-value"
    row = microsoft_configuration_rows["MICROSOFT_CLIENT_SECRET"]
    row.value = encrypt_data(secret)
    row.save()
    return secret
