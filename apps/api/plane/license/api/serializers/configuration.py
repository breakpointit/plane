# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from .base import BaseSerializer
from plane.license.models import InstanceConfiguration
from plane.license.utils.encryption import decrypt_data
from plane.license.utils.masked_configuration import (
    MASKED_CONFIGURATION_KEYS,
    MASKED_SECRET_PLACEHOLDER,
)


class InstanceConfigurationSerializer(BaseSerializer):
    class Meta:
        model = InstanceConfiguration
        fields = "__all__"

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Write-only values are never returned, not even to an instance admin.
        # The form shows a placeholder and sends it back unchanged to keep the
        # stored secret (fork addition; scoped to MASKED_CONFIGURATION_KEYS).
        if instance.key in MASKED_CONFIGURATION_KEYS:
            data["value"] = MASKED_SECRET_PLACEHOLDER if instance.value else ""
            return data
        # Decrypt secrets value
        if instance.is_encrypted and instance.value is not None:
            data["value"] = decrypt_data(instance.value)

        return data
