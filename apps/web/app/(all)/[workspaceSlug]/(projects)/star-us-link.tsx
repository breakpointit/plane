/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useTheme } from "next-themes";
// plane imports
import { useTranslation } from "@plane/i18n";
// assets
import githubBlackImage from "@/app/assets/logos/github-black.png?url";
import githubWhiteImage from "@/app/assets/logos/github-white.png?url";

// AGPL-3.0 section 13 requires a modified version offered over a network to
// prominently offer its users the Corresponding Source. Upstream Plane is not
// that source, and neither is this fork's default branch (`preview`), which
// tracks unmodified upstream -- so this points at the branch actually deployed.
//
// Keep this in step with what is running: if the deployed branch is renamed, or
// merged into the fork's default branch, update or simplify this URL.
const SOURCE_CODE_URL = "https://github.com/breakpointit/plane/tree/feature/entra";

export function SourceCodeLink() {
  // plane hooks
  const { t } = useTranslation();
  // hooks
  const { resolvedTheme } = useTheme();
  const imageSrc = resolvedTheme === "dark" ? githubWhiteImage : githubBlackImage;

  return (
    <a
      aria-label={t("home.source_code")}
      className="flex flex-shrink-0 items-center gap-1.5 rounded-sm bg-layer-2 px-3 py-1.5"
      href={SOURCE_CODE_URL}
      target="_blank"
      rel="noopener noreferrer"
    >
      <img src={imageSrc} className="h-4 w-4 object-contain" alt="GitHub Logo" aria-hidden="true" />
      <span className="hidden text-11 font-medium sm:hidden md:block">{t("home.source_code")}</span>
    </a>
  );
}
