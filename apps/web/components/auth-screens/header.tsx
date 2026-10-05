/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import React from "react";
import Link from "next/link";
import { useTranslation } from "@plane/i18n";
import { PlaneLockup } from "@plane/blocks/icons";
import { PageHead } from "@/components/core/page-title";
import { EAuthModes } from "@/helpers/authentication.helper";

const authContentMap = {
  [EAuthModes.SIGN_IN]: { pageTitle: "Sign up" },
  [EAuthModes.SIGN_UP]: { pageTitle: "Sign in" },
};

type AuthHeaderProps = {
  type: EAuthModes;
};

export function AuthHeader({ type }: AuthHeaderProps) {
  const { t } = useTranslation();

  // The sign-in/sign-up toggle is deliberately omitted: this instance authenticates
  // through Microsoft Entra ID only, so both routes run the identical SSO flow and
  // the link would just bounce the user between two identical screens.
  return <AuthHeaderBase pageTitle={t(authContentMap[type].pageTitle)} />;
}

type TAuthHeaderBase = {
  pageTitle: string;
  additionalAction?: React.ReactNode;
};

export function AuthHeaderBase(props: TAuthHeaderBase) {
  const { pageTitle, additionalAction } = props;
  return (
    <>
      <PageHead title={pageTitle + " - Plane"} />
      <div className="sticky top-0 flex w-full flex-shrink-0 items-center justify-between gap-6">
        <Link href="/">
          <PlaneLockup height={20} width={95} className="text-primary" />
        </Link>
        {additionalAction}
      </div>
    </>
  );
}
