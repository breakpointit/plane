/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { observer } from "mobx-react";
import useSWR from "swr";
// plane internal packages
import { Switch } from "@makeplane/propel/components/switch";
// assets
import microsoftLogo from "@/app/assets/logos/microsoft-logo.svg?url";
// components
import { AuthenticationMethodCard } from "@/components/authentication/authentication-method-card";
import { PageWrapper } from "@/components/common/page-wrapper";
import { Skeleton } from "@/components/common/skeleton";
import { setPromiseToast } from "@plane/blocks/toast";
// hooks
import { useInstance } from "@/hooks/store";
// types
import type { Route } from "./+types/page";
// local components
import { InstanceMicrosoftConfigForm } from "./form";

const InstanceMicrosoftAuthenticationPage = observer(function InstanceMicrosoftAuthenticationPage() {
  // store hooks
  const { fetchInstanceConfigurations, formattedConfig, updateInstanceConfigurations } = useInstance();
  // state
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  // derived values
  const enableMicrosoftConfig = formattedConfig?.IS_MICROSOFT_ENABLED ?? "";

  useSWR("INSTANCE_CONFIGURATIONS", () => fetchInstanceConfigurations());

  const updateConfig = async (key: "IS_MICROSOFT_ENABLED", value: string) => {
    setIsSubmitting(true);
    const payload = { [key]: value };
    const updateConfigPromise = updateInstanceConfigurations(payload);
    setPromiseToast(updateConfigPromise, {
      loading: "Saving Configuration",
      success: {
        title: "Configuration saved",
        message: () => `Microsoft Entra ID authentication is now ${value === "1" ? "active" : "disabled"}.`,
      },
      error: {
        title: "Error",
        // The API rejects enabling Microsoft without a complete set of credentials,
        // so surface whatever reason it gave rather than a generic message.
        message: (err: unknown) => (err as { error?: string } | undefined)?.error ?? "Failed to save configuration",
      },
    });
    await updateConfigPromise
      .then(() => {
        setIsSubmitting(false);
      })
      .catch((err) => {
        console.error(err);
        setIsSubmitting(false);
      });
  };

  const isMicrosoftEnabled = enableMicrosoftConfig === "1";

  return (
    <PageWrapper
      customHeader={
        <AuthenticationMethodCard
          name="Microsoft Entra ID"
          description="Allow members to log in or sign up to Plane with their Microsoft Entra ID accounts."
          icon={<img src={microsoftLogo} height={24} width={24} alt="Microsoft Logo" />}
          config={
            <Switch
              checked={isMicrosoftEnabled}
              onCheckedChange={() => {
                updateConfig("IS_MICROSOFT_ENABLED", isMicrosoftEnabled ? "0" : "1");
              }}
              size="sm"
              disabled={isSubmitting || !formattedConfig}
            />
          }
          disabled={isSubmitting || !formattedConfig}
          withBorder={false}
        />
      }
    >
      {formattedConfig ? (
        <InstanceMicrosoftConfigForm config={formattedConfig} />
      ) : (
        <Skeleton className="space-y-8">
          <Skeleton.Item height="50px" width="25%" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" width="50%" />
        </Skeleton>
      )}
    </PageWrapper>
  );
});

export const meta: Route.MetaFunction = () => [{ title: "Microsoft Entra ID Authentication - God Mode" }];

export default InstanceMicrosoftAuthenticationPage;
