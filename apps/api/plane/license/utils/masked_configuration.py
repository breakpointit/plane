# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Write-only instance configuration values (fork addition).

Upstream returns every stored secret to the God Mode browser in cleartext so the
provider forms can pre-fill their password inputs. For Microsoft Entra ID the
client secret is treated as write-only instead: reads return a placeholder, and a
write that carries the placeholder (or a blank value) leaves the stored secret
untouched.

The key set is deliberately narrow so no existing provider changes behaviour.
"""

# Python imports
import os

# Module imports
from plane.license.utils.instance_value import get_configuration_value

__all__ = [
    "MASKED_CONFIGURATION_KEYS",
    "MASKED_SECRET_PLACEHOLDER",
    "is_masked_value",
    "validate_microsoft_configuration",
]

# Values never returned to the browser once stored.
MASKED_CONFIGURATION_KEYS = frozenset({"MICROSOFT_CLIENT_SECRET"})

# What the God Mode form shows in place of a stored secret. Submitting it back
# unchanged is a no-op, which is what makes "leave blank to keep" work.
MASKED_SECRET_PLACEHOLDER = "••••••••••••"

# Credentials that must all be present before Microsoft authentication can be enabled.
MICROSOFT_REQUIRED_KEYS = ("MICROSOFT_TENANT_ID", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET")


def is_masked_value(key, value):
    """True when an incoming value for a masked key should be ignored (keep existing)."""
    if key not in MASKED_CONFIGURATION_KEYS:
        return False
    if value is None:
        return True
    value = str(value).strip()
    return value == "" or value == MASKED_SECRET_PLACEHOLDER


def validate_microsoft_configuration(payload):
    """
    Validate a God Mode configuration update against the resulting Microsoft state.

    Backend validation is mandatory here: the frontend gates the enable toggle on
    the credentials being present, but the API must not accept an enabled provider
    with missing or malformed credentials regardless of what the client sends.

    Returns an error string, or None when the update is acceptable.
    """
    microsoft_keys = set(MICROSOFT_REQUIRED_KEYS) | {"IS_MICROSOFT_ENABLED"}
    if not microsoft_keys & set(payload.keys()):
        return None

    current = dict(
        zip(
            ("IS_MICROSOFT_ENABLED", *MICROSOFT_REQUIRED_KEYS),
            get_configuration_value(
                [
                    {
                        "key": "IS_MICROSOFT_ENABLED",
                        "default": os.environ.get("IS_MICROSOFT_ENABLED", "0"),
                    },
                    *[{"key": key, "default": os.environ.get(key)} for key in MICROSOFT_REQUIRED_KEYS],
                ]
            ),
        )
    )

    def resolved(key):
        """The value this key will hold once the update is applied."""
        if key not in payload:
            return (current.get(key) or "").strip()
        # A blank or placeholder secret preserves whatever is already stored.
        if is_masked_value(key, payload.get(key)):
            return (current.get(key) or "").strip()
        value = payload.get(key)
        return "" if value is None else str(value).strip()

    will_be_enabled = resolved("IS_MICROSOFT_ENABLED") == "1"
    if not will_be_enabled:
        return None

    missing = [key for key in MICROSOFT_REQUIRED_KEYS if not resolved(key)]
    if missing:
        return (
            "Microsoft Entra ID authentication requires a tenant ID, client ID and client secret. "
            f"Missing or cleared: {', '.join(missing)}."
        )

    # Imported here rather than at module scope: the serializer only needs the two
    # constants above, and this keeps it from pulling in the whole auth adapter stack.
    from plane.authentication.adapter.error import AuthenticationException
    from plane.authentication.provider.oauth.microsoft import validate_tenant_id

    try:
        validate_tenant_id(resolved("MICROSOFT_TENANT_ID"))
    except AuthenticationException:
        return (
            "MICROSOFT_TENANT_ID must be a directory (tenant) ID or a verified domain, "
            "not a URL. Multi-tenant values such as 'common' are not supported."
        )

    return None
