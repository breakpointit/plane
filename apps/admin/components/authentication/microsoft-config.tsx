/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { observer } from "mobx-react";
import Link from "next/link";
import { SettingsOutline } from "@makeplane/propel/icons";
import { AnchorButton } from "@makeplane/propel/components/anchor-button";
import { Button } from "@makeplane/propel/components/button";
import { Switch } from "@makeplane/propel/components/switch";
// plane internal packages
import type { TInstanceAuthenticationMethodKeys } from "@plane/types";
// hooks
import { useInstance } from "@/hooks/store";

type Props = {
  disabled: boolean;
  updateConfig: (key: TInstanceAuthenticationMethodKeys, value: string) => void;
};

export const MicrosoftConfiguration = observer(function MicrosoftConfiguration(props: Props) {
  const { disabled, updateConfig } = props;
  // store hooks
  const { formattedConfig } = useInstance();
  // derived values
  const microsoftConfig = formattedConfig?.IS_MICROSOFT_ENABLED ?? "";
  // The client secret is write-only: the API returns a placeholder once one is
  // stored, which is still truthy, so this check works without ever seeing it.
  const isMicrosoftConfigured =
    !!formattedConfig?.MICROSOFT_TENANT_ID &&
    !!formattedConfig?.MICROSOFT_CLIENT_ID &&
    !!formattedConfig?.MICROSOFT_CLIENT_SECRET;

  return (
    <>
      {isMicrosoftConfigured ? (
        <div className="flex items-center gap-4">
          <AnchorButton variant="primary" size="sm" render={<Link href="/authentication/microsoft" />} label="Edit" />
          <Switch
            checked={Boolean(parseInt(microsoftConfig))}
            onCheckedChange={() => {
              Boolean(parseInt(microsoftConfig)) === true
                ? updateConfig("IS_MICROSOFT_ENABLED", "0")
                : updateConfig("IS_MICROSOFT_ENABLED", "1");
            }}
            size="sm"
            disabled={disabled}
          />
        </div>
      ) : (
        <Button
          variant="secondary"
          size="sm"
          stretch="auto"
          nativeButton={false}
          render={<Link href="/authentication/microsoft" />}
          icon={<SettingsOutline className="h-4 w-4 p-0.5 text-tertiary" />}
          label="Configure"
        />
      )}
    </>
  );
});
