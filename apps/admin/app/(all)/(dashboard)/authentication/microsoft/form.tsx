/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { isEmpty } from "lodash-es";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { MonitorOutline } from "@makeplane/propel/icons";
// plane internal packages
import { API_BASE_URL } from "@plane/constants";
import { Button } from "@makeplane/propel/components/button";
import type { IFormattedInstanceConfiguration, TInstanceMicrosoftAuthenticationConfigurationKeys } from "@plane/types";
// components
import { CodeBlock } from "@/components/common/code-block";
import { ConfirmDiscardModal } from "@/components/common/confirm-discard-modal";
import type { TControllerInputFormField } from "@/components/common/controller-input";
import { ControllerInput } from "@/components/common/controller-input";
import type { TControllerSwitchFormField } from "@/components/common/controller-switch";
import { ControllerSwitch } from "@/components/common/controller-switch";
import type { TCopyField } from "@/components/common/copy-field";
import { CopyField } from "@/components/common/copy-field";
// hooks
import { useInstance } from "@/hooks/store";
// providers
import { setToast } from "@plane/blocks/toast";

type Props = {
  config: IFormattedInstanceConfiguration;
};

type MicrosoftConfigFormValues = Record<TInstanceMicrosoftAuthenticationConfigurationKeys, string>;

const MICROSOFT_FORM_SWITCH_FIELD: TControllerSwitchFormField<MicrosoftConfigFormValues> = {
  name: "ENABLE_MICROSOFT_SYNC",
  label: "Microsoft Entra ID",
};

const ENTRA_APP_REGISTRATIONS_URL = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade";

export function InstanceMicrosoftConfigForm(props: Props) {
  const { config } = props;
  // states
  const [isDiscardChangesModalOpen, setIsDiscardChangesModalOpen] = useState(false);
  // store hooks
  const { updateInstanceConfigurations } = useInstance();
  // The API never returns the stored client secret. Once one exists it returns a
  // masked placeholder, which is what lands in this field and what gets sent back
  // untouched when the administrator does not type a replacement.
  const isClientSecretConfigured = !isEmpty(config["MICROSOFT_CLIENT_SECRET"]);
  // form data
  const {
    handleSubmit,
    control,
    reset,
    formState: { errors, isDirty, isSubmitting },
  } = useForm<MicrosoftConfigFormValues>({
    defaultValues: {
      MICROSOFT_TENANT_ID: config["MICROSOFT_TENANT_ID"],
      MICROSOFT_CLIENT_ID: config["MICROSOFT_CLIENT_ID"],
      MICROSOFT_CLIENT_SECRET: config["MICROSOFT_CLIENT_SECRET"],
      ENABLE_MICROSOFT_SYNC: config["ENABLE_MICROSOFT_SYNC"] || "0",
    },
  });

  const originURL = !isEmpty(API_BASE_URL) ? API_BASE_URL : typeof window !== "undefined" ? window.location.origin : "";

  const MICROSOFT_FORM_FIELDS: TControllerInputFormField<MicrosoftConfigFormValues>[] = [
    {
      key: "MICROSOFT_TENANT_ID",
      type: "text",
      label: "Tenant ID",
      description: (
        <>
          The Directory (tenant) ID of your Entra app registration, or a verified domain such as{" "}
          <CodeBlock darkerShade>contoso.onmicrosoft.com</CodeBlock>. Sign-in is restricted to this single tenant, so
          shared values like <CodeBlock darkerShade>common</CodeBlock> are not accepted.{" "}
          <a
            href={ENTRA_APP_REGISTRATIONS_URL}
            target="_blank"
            className="text-accent-primary hover:underline"
            rel="noreferrer"
            aria-label="Microsoft Entra app registrations"
          >
            Find it here.
          </a>
        </>
      ),
      placeholder: "00000000-0000-0000-0000-000000000000",
      error: Boolean(errors.MICROSOFT_TENANT_ID),
      required: true,
    },
    {
      key: "MICROSOFT_CLIENT_ID",
      type: "text",
      label: "Client ID",
      description: (
        <>
          The Application (client) ID shown on your Entra app registration&apos;s Overview page.{" "}
          <a
            href={ENTRA_APP_REGISTRATIONS_URL}
            target="_blank"
            className="text-accent-primary hover:underline"
            rel="noreferrer"
            aria-label="Microsoft Entra app registrations"
          >
            Find it here.
          </a>
        </>
      ),
      placeholder: "00000000-0000-0000-0000-000000000000",
      error: Boolean(errors.MICROSOFT_CLIENT_ID),
      required: true,
    },
    {
      key: "MICROSOFT_CLIENT_SECRET",
      type: "password",
      label: "Client secret",
      description: (
        <>
          {isClientSecretConfigured ? (
            <>
              Client secret configured. It is stored encrypted and never sent back to this page — leave this field
              untouched to keep it, or type a new secret to replace it.{" "}
            </>
          ) : (
            <>
              Create one under <CodeBlock darkerShade>Certificates &amp; secrets</CodeBlock> in your Entra app
              registration and paste the secret <em>Value</em> (not the Secret ID).{" "}
            </>
          )}
          <a
            href={ENTRA_APP_REGISTRATIONS_URL}
            target="_blank"
            className="text-accent-primary hover:underline"
            rel="noreferrer"
            aria-label="Microsoft Entra app registrations"
          >
            Manage secrets here.
          </a>
        </>
      ),
      placeholder: "Client secret value",
      error: Boolean(errors.MICROSOFT_CLIENT_SECRET),
      required: true,
    },
  ];

  const MICROSOFT_SERVICE_DETAILS: TCopyField[] = [
    {
      key: "Callback_URI",
      label: "Redirect URI",
      url: `${originURL}/auth/microsoft/callback/`,
      description: (
        <p>
          We will auto-generate this. Add it to your Entra app registration under{" "}
          <CodeBlock darkerShade>Authentication</CodeBlock> &rarr; <CodeBlock darkerShade>Web</CodeBlock> &rarr;{" "}
          <CodeBlock darkerShade>Redirect URIs</CodeBlock>. It must match exactly, including the trailing slash.
        </p>
      ),
    },
  ];

  const onSubmit = async (formData: MicrosoftConfigFormValues) => {
    // The client secret is sent as-is. When it still holds the masked placeholder
    // the server treats it as "keep the existing secret".
    const payload: Partial<MicrosoftConfigFormValues> = { ...formData };

    try {
      const response = await updateInstanceConfigurations(payload);
      setToast({
        type: "success",
        title: "Done!",
        message: "Your Microsoft Entra ID authentication is configured. You should test it now.",
      });
      reset({
        MICROSOFT_TENANT_ID: response.find((item) => item.key === "MICROSOFT_TENANT_ID")?.value,
        MICROSOFT_CLIENT_ID: response.find((item) => item.key === "MICROSOFT_CLIENT_ID")?.value,
        MICROSOFT_CLIENT_SECRET: response.find((item) => item.key === "MICROSOFT_CLIENT_SECRET")?.value,
        ENABLE_MICROSOFT_SYNC: response.find((item) => item.key === "ENABLE_MICROSOFT_SYNC")?.value,
      });
    } catch (err) {
      setToast({
        type: "error",
        title: "Error",
        message: (err as { error?: string })?.error ?? "Failed to save configuration",
      });
    }
  };

  const handleGoBack = (e: React.MouseEvent<HTMLAnchorElement, MouseEvent>) => {
    if (isDirty) {
      e.preventDefault();
      setIsDiscardChangesModalOpen(true);
    }
  };

  return (
    <>
      <ConfirmDiscardModal
        isOpen={isDiscardChangesModalOpen}
        onDiscardHref="/authentication"
        handleClose={() => setIsDiscardChangesModalOpen(false)}
      />
      <div className="flex flex-col gap-8">
        <div className="grid w-full grid-cols-2 gap-x-12 gap-y-8">
          <div className="col-span-2 flex flex-col gap-y-4 pt-1 md:col-span-1">
            <div className="pt-2.5 text-18 font-medium">Microsoft-provided details for Plane</div>
            {MICROSOFT_FORM_FIELDS.map((field) => (
              <ControllerInput
                key={field.key}
                control={control}
                type={field.type}
                name={field.key}
                label={field.label}
                description={field.description}
                placeholder={field.placeholder}
                error={field.error}
                required={field.required}
              />
            ))}
            <ControllerSwitch control={control} field={MICROSOFT_FORM_SWITCH_FIELD} />
            <div className="flex flex-col gap-1 pt-4">
              <div className="flex items-center gap-4">
                <Button
                  variant="primary"
                  size="md"
                  stretch="auto"
                  onClick={(e) => void handleSubmit(onSubmit)(e)}
                  loading={isSubmitting}
                  disabled={!isDirty}
                  label={isSubmitting ? "Saving" : "Save changes"}
                />
                <Button
                  variant="secondary"
                  size="md"
                  stretch="auto"
                  nativeButton={false}
                  render={<Link href="/authentication" onClick={handleGoBack} />}
                  label="Go back"
                />
              </div>
            </div>
          </div>
          <div className="col-span-2 flex flex-col gap-y-6 md:col-span-1">
            <div className="pt-2 text-18 font-medium">Plane-provided details for Microsoft</div>

            <div className="flex flex-col overflow-hidden rounded-lg">
              <div className="flex items-center gap-x-3 bg-layer-3 px-6 py-3 text-11 font-medium text-secondary uppercase">
                <MonitorOutline className="h-3 w-3" />
                Web
              </div>
              <div className="flex flex-col gap-y-4 bg-layer-1 px-6 py-4">
                {MICROSOFT_SERVICE_DETAILS.map((field) => (
                  <CopyField key={field.key} label={field.label} url={field.url} description={field.description} />
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
