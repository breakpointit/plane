/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { observer } from "mobx-react";
// plane imports
import { setToast } from "@plane/blocks/toast";
import type { IWorkspaceMemberInvitation, TOnboardingStep, TOnboardingSteps, TUserProfile } from "@plane/types";
import { EOnboardingSteps } from "@plane/types";
// hooks
import { useInstance } from "@/hooks/store/use-instance";
import { useWorkspace } from "@/hooks/store/use-workspace";
import { useUser, useUserProfile } from "@/hooks/store/user";
// local components
import { OnboardingHeader } from "./header";
import { OnboardingStepRoot } from "./steps";

type Props = {
  invitations?: IWorkspaceMemberInvitation[];
};

export const OnboardingRoot = observer(function OnboardingRoot({ invitations = [] }: Props) {
  const [currentStep, setCurrentStep] = useState<TOnboardingStep>(EOnboardingSteps.PROFILE_SETUP);
  // store hooks
  const { data: user } = useUser();
  const { data: userProfile, updateUserProfile, finishUserOnboarding } = useUserProfile();
  const { workspaces } = useWorkspace();
  const { config: instanceConfig } = useInstance();

  const workspacesList = Object.values(workspaces ?? {});
  const isSelfManaged = instanceConfig?.is_self_managed;

  // Calculate total steps based on whether invitations are available
  const hasInvitations = invitations.length > 0;

  // complete onboarding
  const finishOnboarding = useCallback(async () => {
    if (!user) return;
    try {
      await finishUserOnboarding();
    } catch (_error) {
      setToast({
        type: "error",
        title: "Failed",
        message: "Failed to finish onboarding, Please try again later.",
      });
    }
  }, [user, finishUserOnboarding]);

  // handle step change
  const stepChange = useCallback(
    async (steps: Partial<TOnboardingSteps>) => {
      if (!user) return;

      const payload: Partial<TUserProfile> = {
        onboarding_step: {
          ...userProfile.onboarding_step,
          ...steps,
        },
      };

      await updateUserProfile(payload);
    },
    [user, userProfile, updateUserProfile]
  );

  const handleStepChange = useCallback(
    (step: EOnboardingSteps, skipInvites?: boolean) => {
      switch (step) {
        case EOnboardingSteps.PROFILE_SETUP:
          if (isSelfManaged) {
            // Skip role & use case steps for self-hosted
            stepChange({ profile_complete: true });
            if (workspacesList.length > 0) finishOnboarding();
            else setCurrentStep(EOnboardingSteps.WORKSPACE_CREATE_OR_JOIN);
          } else {
            setCurrentStep(EOnboardingSteps.ROLE_SETUP);
          }
          break;
        case EOnboardingSteps.ROLE_SETUP:
          setCurrentStep(EOnboardingSteps.USE_CASE_SETUP);
          break;
        case EOnboardingSteps.USE_CASE_SETUP:
          stepChange({ profile_complete: true });
          if (workspacesList.length > 0) finishOnboarding();
          else setCurrentStep(EOnboardingSteps.WORKSPACE_CREATE_OR_JOIN);
          break;
        case EOnboardingSteps.WORKSPACE_CREATE_OR_JOIN:
          if (skipInvites) finishOnboarding();
          else {
            setCurrentStep(EOnboardingSteps.INVITE_MEMBERS);
            stepChange({ workspace_create: true });
          }
          break;
        case EOnboardingSteps.INVITE_MEMBERS:
          stepChange({ workspace_invite: true });
          finishOnboarding();
          break;
      }
    },
    [stepChange, finishOnboarding, workspacesList, isSelfManaged]
  );

  const updateCurrentStep = (step: EOnboardingSteps) => setCurrentStep(step);

  useEffect(() => {
    const handleInitialStep = () => {
      if (
        userProfile?.onboarding_step?.profile_complete &&
        !userProfile?.onboarding_step?.workspace_create &&
        !userProfile?.onboarding_step?.workspace_join
      ) {
        setCurrentStep(EOnboardingSteps.WORKSPACE_CREATE_OR_JOIN);
      }
      if (
        userProfile?.onboarding_step?.profile_complete &&
        userProfile?.onboarding_step?.workspace_create &&
        !userProfile?.onboarding_step?.workspace_invite
      ) {
        setCurrentStep(EOnboardingSteps.INVITE_MEMBERS);
      }
    };

    handleInitialStep();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Skip the profile step when it has nothing left to ask for. An SSO user arrives
  // with their name already supplied by the identity provider, and needs no password
  // when one is set or when password sign-in is disabled instance-wide -- so the step
  // would only ask them to retype a name the IdP overwrites on their next sign-in.
  // Users who genuinely have something to fill in (email/magic-code sign-ups, or an
  // instance where a password is still required) are unaffected.
  const hasAutoSkippedProfileSetup = useRef(false);
  useEffect(() => {
    if (hasAutoSkippedProfileSetup.current) return;
    if (!user || !userProfile) return;
    if (currentStep !== EOnboardingSteps.PROFILE_SETUP) return;
    if (userProfile.onboarding_step?.profile_complete) return;

    const hasName = Boolean(user.first_name?.trim());
    const needsPassword = Boolean(user.is_password_autoset) && Boolean(instanceConfig?.is_email_password_enabled);
    if (!hasName || needsPassword) return;

    hasAutoSkippedProfileSetup.current = true;
    handleStepChange(EOnboardingSteps.PROFILE_SETUP);
  }, [user, userProfile, currentStep, instanceConfig, handleStepChange]);

  return (
    <div className="flex h-full flex-col">
      {/* Header with progress */}
      <OnboardingHeader
        currentStep={currentStep}
        updateCurrentStep={updateCurrentStep}
        hasInvitations={hasInvitations}
      />

      {/* Main content area */}
      <OnboardingStepRoot currentStep={currentStep} invitations={invitations} handleStepChange={handleStepChange} />
    </div>
  );
});
