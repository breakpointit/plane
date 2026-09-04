/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

// plane imports
import { useSearchParams } from "next/navigation";
import { API_BASE_URL } from "@plane/constants";
import type { TOAuthConfigs } from "@plane/types";
// assets
import microsoftLogo from "@/app/assets/logos/microsoft-logo.svg?url";
// hooks
import { useInstance } from "@/hooks/store/use-instance";

/**
 * Microsoft Entra ID sign-in option (fork addition).
 *
 * Kept alongside `core.tsx` rather than inside it so merges from upstream Plane
 * stay conflict-free. The browser only ever learns whether the provider is
 * enabled; the authorization URL is built server-side by the initiation endpoint.
 */
export const useMicrosoftOAuthConfig = (oauthActionText: string): TOAuthConfigs => {
  const searchParams = useSearchParams();
  const next_path = searchParams.get("next_path");
  const { config } = useInstance();

  const isMicrosoftEnabled = config?.is_microsoft_enabled ?? false;

  return {
    isOAuthEnabled: isMicrosoftEnabled,
    oAuthOptions: [
      {
        id: "microsoft",
        text: `${oauthActionText} with Microsoft`,
        icon: <img src={microsoftLogo} height={18} width={18} alt="Microsoft Logo" />,
        onClick: () => {
          window.location.assign(`${API_BASE_URL}/auth/microsoft/${next_path ? `?next_path=${next_path}` : ``}`);
        },
        enabled: isMicrosoftEnabled,
      },
    ],
  };
};
