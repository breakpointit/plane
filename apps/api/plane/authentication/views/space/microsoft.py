# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import hmac
import time
import uuid
from urllib.parse import urlencode

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
from plane.authentication.views.app.microsoft import (
    MICROSOFT_STATE_TTL,
    clear_microsoft_session_state,
)
from plane.license.models import Instance
from plane.utils.path_validator import validate_next_path


class MicrosoftOauthInitiateSpaceEndpoint(View):
    def get(self, request):
        # Get host and next path
        request.session["host"] = base_host(request=request, is_space=True)
        next_path = request.GET.get("next_path")
        if next_path:
            request.session["next_path"] = str(validate_next_path(next_path))

        def _error_redirect(exc):
            params = exc.get_error_dict()
            if next_path:
                params["next_path"] = str(validate_next_path(next_path))
            return HttpResponseRedirect(f"{base_host(request=request, is_space=True)}?{urlencode(params)}")

        # Check instance configuration
        instance = Instance.objects.first()
        if instance is None or not instance.is_setup_done:
            return _error_redirect(
                AuthenticationException(
                    error_code=AUTHENTICATION_ERROR_CODES["INSTANCE_NOT_CONFIGURED"],
                    error_message="INSTANCE_NOT_CONFIGURED",
                )
            )

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
            return _error_redirect(e)


class MicrosoftCallbackSpaceEndpoint(View):
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

        def _error_redirect(exc):
            params = exc.get_error_dict()
            if next_path:
                params["next_path"] = str(validate_next_path(next_path))
            return HttpResponseRedirect(f"{base_host(request=request, is_space=True)}?{urlencode(params)}")

        def _provider_error():
            return _error_redirect(
                AuthenticationException(
                    error_code=AUTHENTICATION_ERROR_CODES["MICROSOFT_OAUTH_PROVIDER_ERROR"],
                    error_message="MICROSOFT_OAUTH_PROVIDER_ERROR",
                )
            )

        # Reject missing, mismatched or expired state before anything else.
        if not state or not session_state or not hmac.compare_digest(str(state), str(session_state)):
            return _provider_error()

        if not isinstance(issued_at, int) or (time.time() - issued_at) > MICROSOFT_STATE_TTL:
            return _provider_error()

        if not code:
            return _provider_error()

        try:
            provider = MicrosoftOAuthProvider(request=request, code=code, nonce=nonce, code_verifier=code_verifier)
            user = provider.authenticate()
            # Login the user and record his device info
            user_login(request=request, user=user, is_space=True)
            # redirect to referer path
            url = (
                f"{base_host(request=request, is_space=True)}{str(validate_next_path(next_path)) if next_path else ''}"
            )
            return HttpResponseRedirect(url)
        except AuthenticationException as e:
            return _error_redirect(e)
