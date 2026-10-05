/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

// plane imports
import type { TOAuthConfigs } from "@plane/types";
// local imports
import { useCoreOAuthConfig } from "./core";
import { useExtendedOAuthConfig } from "./extended";
import { useMicrosoftOAuthConfig } from "./microsoft";

export const useOAuthConfig = (oauthActionText: string = "Continue"): TOAuthConfigs => {
  const coreOAuthConfig = useCoreOAuthConfig(oauthActionText);
  const extendedOAuthConfig = useExtendedOAuthConfig(oauthActionText);
  // Microsoft Entra ID (fork addition), merged in as a third source so `core.tsx`
  // stays byte-identical to upstream.
  const microsoftOAuthConfig = useMicrosoftOAuthConfig(oauthActionText);
  return {
    isOAuthEnabled:
      coreOAuthConfig.isOAuthEnabled || extendedOAuthConfig.isOAuthEnabled || microsoftOAuthConfig.isOAuthEnabled,
    oAuthOptions: [
      ...coreOAuthConfig.oAuthOptions,
      ...extendedOAuthConfig.oAuthOptions,
      ...microsoftOAuthConfig.oAuthOptions,
    ],
  };
};
