/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

// plane internal packages
import type { TGetBaseAuthenticationModeProps, TInstanceAuthenticationModes } from "@plane/types";
// assets
import microsoftLogo from "@/app/assets/logos/microsoft-logo.svg?url";
// components
import { MicrosoftConfiguration } from "@/components/authentication/microsoft-config";

/**
 * Microsoft Entra ID authentication mode (fork addition).
 *
 * Kept alongside `core.tsx` rather than inside it so merges from upstream Plane
 * stay conflict-free.
 */
export const getMicrosoftAuthenticationMode = ({
  disabled,
  updateConfig,
}: TGetBaseAuthenticationModeProps): TInstanceAuthenticationModes => ({
  key: "microsoft",
  name: "Microsoft Entra ID",
  description: "Allow members to log in or sign up to Plane with their Microsoft Entra ID accounts.",
  icon: <img src={microsoftLogo} height={20} width={20} alt="Microsoft Logo" />,
  config: <MicrosoftConfiguration disabled={disabled} updateConfig={updateConfig} />,
  enabledConfigKey: "IS_MICROSOFT_ENABLED",
});
