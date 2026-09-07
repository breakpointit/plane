# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import hmac
import time
import uuid

# Django import
from django.http import HttpResponseRedirect
from django.views import View

# Module imports
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)
from plane.authentication.provider.oauth.microsoft import (
    MicrosoftOAuthProvider,
    generate_code_challenge,
    generate_code_verifier,
    generate_nonce,
)
from plane.authentication.utils.host import base_host
from plane.authentication.utils.login import user_login
from plane.authentication.utils.redirection_path import get_redirection_path
from plane.authentication.utils.user_auth_workflow import post_user_auth_workflow
from plane.license.models import Instance
from plane.utils.path_validator import get_safe_redirect_url

# The authorization request is only valid for a short window. State that outlives
# it is rejected even if the session is still alive.
MICROSOFT_STATE_TTL = 10 * 60

# Session keys holding the single-use values created at initiation.
MICROSOFT_SESSION_KEYS = (
    "state",
    "microsoft_nonce",
    "microsoft_code_verifier",
    "microsoft_state_issued_at",
)


def clear_microsoft_session_state(request):
    """State, nonce and code verifier are strictly single-use."""
    for key in MICROSOFT_SESSION_KEYS:
        request.session.pop(key, None)


class MicrosoftOauthInitiateEndpoint(View):
    def get(self, request):
        request.session["host"] = base_host(request=request, is_app=True)
        next_path = request.GET.get("next_path")
        if next_path:
            request.session["next_path"] = str(next_path)

        # Check instance configuration
        instance = Instance.objects.first()
        if instance is None or not instance.is_setup_done:
            exc = AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["INSTANCE_NOT_CONFIGURED"],
                error_message="INSTANCE_NOT_CONFIGURED",
            )
            params = exc.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            return HttpResponseRedirect(url)

        try:
            state = uuid.uuid4().hex
            nonce = generate_nonce()
            code_verifier = generate_code_verifier()
            provider = MicrosoftOAuthProvider(
                request=request,
                state=state,
                nonce=nonce,
                code_challenge=generate_code_challenge(code_verifier),
            )
            request.session["state"] = state
            request.session["microsoft_nonce"] = nonce
            request.session["microsoft_code_verifier"] = code_verifier
            request.session["microsoft_state_issued_at"] = int(time.time())
            auth_url = provider.get_auth_url()
            return HttpResponseRedirect(auth_url)
        except AuthenticationException as e:
            params = e.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            return HttpResponseRedirect(url)


class MicrosoftCallbackEndpoint(View):
    def get(self, request):
        code = request.GET.get("code")
        state = request.GET.get("state")
        next_path = request.session.get("next_path")

        session_state = request.session.get("state")
        nonce = request.session.get("microsoft_nonce")
        code_verifier = request.session.get("microsoft_code_verifier")
        issued_at = request.session.get("microsoft_state_issued_at")

        # Whatever happens next, these values must not be replayable.
        clear_microsoft_session_state(request)

        def _error_redirect(error_code):
            exc = AuthenticationException(error_code=AUTHENTICATION_ERROR_CODES[error_code], error_message=error_code)
            return HttpResponseRedirect(
                get_safe_redirect_url(
                    base_url=base_host(request=request, is_app=True),
                    next_path=next_path,
                    params=exc.get_error_dict(),
                )
            )

        # Reject missing, mismatched or expired state before anything else.
        if not state or not session_state or not hmac.compare_digest(str(state), str(session_state)):
            return _error_redirect("MICROSOFT_OAUTH_PROVIDER_ERROR")

        if not isinstance(issued_at, int) or (time.time() - issued_at) > MICROSOFT_STATE_TTL:
            return _error_redirect("MICROSOFT_OAUTH_PROVIDER_ERROR")

        if not code:
            return _error_redirect("MICROSOFT_OAUTH_PROVIDER_ERROR")

        try:
            provider = MicrosoftOAuthProvider(
                request=request,
                code=code,
                nonce=nonce,
                code_verifier=code_verifier,
                callback=post_user_auth_workflow,
            )
            user = provider.authenticate()
            # Login the user and record his device info
            user_login(request=request, user=user, is_app=True)
            # Get the redirection path
            if next_path:
                path = next_path
            else:
                path = get_redirection_path(user=user)
            url = get_safe_redirect_url(base_url=base_host(request=request, is_app=True), next_path=path, params={})
            return HttpResponseRedirect(url)
        except AuthenticationException as e:
            params = e.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            return HttpResponseRedirect(url)
