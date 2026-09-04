# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import os

# Microsoft Entra ID (fork addition).
#
# Kept in its own module rather than appended to `core.py` so that merges from
# upstream never touch this block. Shapes and defaults deliberately mirror the
# Google / Gitea entries in `core.py`.
microsoft_config_variables = [
    {
        "key": "IS_MICROSOFT_ENABLED",
        "value": os.environ.get("IS_MICROSOFT_ENABLED", "0"),
        "category": "MICROSOFT",
        "is_encrypted": False,
    },
    {
        "key": "MICROSOFT_TENANT_ID",
        "value": os.environ.get("MICROSOFT_TENANT_ID"),
        "category": "MICROSOFT",
        "is_encrypted": False,
    },
    {
        "key": "MICROSOFT_CLIENT_ID",
        "value": os.environ.get("MICROSOFT_CLIENT_ID"),
        "category": "MICROSOFT",
        "is_encrypted": False,
    },
    {
        "key": "MICROSOFT_CLIENT_SECRET",
        "value": os.environ.get("MICROSOFT_CLIENT_SECRET"),
        "category": "MICROSOFT",
        "is_encrypted": True,
    },
    {
        "key": "ENABLE_MICROSOFT_SYNC",
        "value": os.environ.get("ENABLE_MICROSOFT_SYNC", "0"),
        "category": "MICROSOFT",
        "is_encrypted": False,
    },
]
