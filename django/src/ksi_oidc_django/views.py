from typing import Optional

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.views import LoginView as DjangoLoginView
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import redirect
from django.http import HttpRequest, HttpResponse
from django.utils.cache import add_never_cache_headers
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.generic.base import View

from ksi_oidc_common.errors import OidcProviderError, OidcError

from ._common import logger, get_oidc_client
from ._consts import SESSION_TOKENS_SESSION_KEY, STATES_SESSION_KEY
from ._user_sessions import login_with_oidc_backend
from .utils import (
    redirect_to_oidc_login,
    is_oidc_auth_backend_enabled,
    is_user_authenticated_with_oidc,
    ensure_middleware_was_applied,
)


class OidcLoginView(View):
    """
    The ksi-django-oidc login view.

    If the user is authenticated, redirects the URL specified in the next query param
    or to `LOGIN_REDIRECT_URL`.

    If `OidcAuthBackend` is enabled, redirects the user directly to the OIDC login page.

    If `OidcAuthBackend` is not enabled, renders the view specified as `fallback_view`.
    The fallback view can be modified when using `.as_view()` like so:
    `OidcLoginView.as_view(fallback_view=some_view)`.

    The path to this view should be set as the value of the `LOGIN_URL` setting.
    """

    # Note that this `fallback_view` must be a class attribute,
    # so that the `View.as_view()` method allows calling
    # `OidcLoginView.as_view(fallback_view=some_view)`.
    fallback_view = staticmethod(DjangoLoginView.as_view())

    def __init__(self, fallback_view=None, **kwargs):
        super().__init__(**kwargs)
        if fallback_view is not None:
            # `staticmethod` is used to avoid binding the `self` argument from `OidcLoginView`.
            self.fallback_view = staticmethod(fallback_view)

    def _get_next_url(self, request):
        next_url = settings.LOGIN_REDIRECT_URL

        if "next" in request.GET:
            next_url_is_valid = url_has_allowed_host_and_scheme(
                request.GET["next"],
                allowed_hosts=request.get_host(),
                require_https=request.is_secure(),
            )
            if next_url_is_valid:
                next_url = request.GET["next"]
            else:
                logger.warning(
                    f"Received an invalid next URL in the login request: {next_url}"
                )

        return next_url

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and request.method in ("GET", "HEAD", "POST"):
            response = redirect(self._get_next_url(request))
            add_never_cache_headers(response)
            return response

        if not is_oidc_auth_backend_enabled():
            # When the fallback view is used, requests with all methods are passed to it.
            # This might be needed if the fallback login view uses an HTML form with `method="post"`.
            return self.fallback_view(request)

        # There is no reason to allow submitting a POST request to the OIDC login endpoint.
        if request.method not in ("GET", "HEAD"):
            return self.http_method_not_allowed(request)

        return redirect_to_oidc_login(request, self._get_next_url(request))


# Apply the never cache `Cache-Control` header values to avoid browser and proxy caches
# from caching the success redirect.
@method_decorator(never_cache, name="dispatch")
class CallbackView(View):
    def _display_login_error(self, description: Optional[str] = None):
        description = description or "Authentication failed"
        # TODO: Replace with a customizable template
        body = f"<h1>Login failed</h1><p>{description}</p>"
        return HttpResponse(body, status=500)

    def _pop_state_entry(self, request, state) -> Optional[dict]:
        if STATES_SESSION_KEY not in request.session:
            return None
        state_entry = request.session[STATES_SESSION_KEY].pop(state, None)

        # Modifying an inner dict does not trigger the session save automatically,
        # setting `request.session.modified` makes sure that the session is saved.
        # See https://docs.djangoproject.com/en/5.2/topics/http/sessions/#when-sessions-are-saved
        request.session.modified = True
        return state_entry

    def get(self, request: HttpRequest):
        # Error handling should generally not redirect to the next page unless `prompt` was set to `None`.
        # If the next page uses a `@login_required`/`@ksi_oidc_login_required` decorator, it might lead to a redirect
        # loop.
        # Requests with `prompt=none` usually come from the `@ksi_oidc_check_sso` decorator, which avoids infinite
        # loops by setting a temporary cookie preventing further redirections.

        if not is_oidc_auth_backend_enabled():
            # It's not this package that triggered the authentication,
            # and authenticating wouldn't be possible anyway without the backend.
            raise SuspiciousOperation(
                "Received a response from the OIDC provider, but OidcAuthBackend is not enabled"
            )

        ensure_middleware_was_applied(request)
        oidc_client = get_oidc_client()

        try:
            authorization_response = oidc_client.parse_authorization_callback_response(
                request.GET
            )
        except OidcProviderError as error:
            state_entry = self._pop_state_entry(request, error.response["state"])
            if state_entry is not None and state_entry["prompt_none"]:
                if error.response["error"] in ("login_required", "interaction_required"):
                    # These errors are expected when `prompt=none` is used, they just indicate
                    # that the user must sign in.
                    logger.debug(
                        f"Received error {error.response['error']} in the CallbackView"
                    )
                else:
                    logger.error(
                        f"Received error {error.response['error']} in the CallbackView:\n"
                        f"Description: {error.response.get('error_description')}",
                    )
                # Always silently return to the next page if the redirect used `prompt=none`
                return redirect(state_entry["next_url"])

            logger.error(
                f"Received error {error.response['error']} in the CallbackView:\n"
                f"Description: {error.response.get('error_description')}",
            )
            return self._display_login_error(error.response.get('error_description'))
        except OidcError as error:
            logger.error(
                f"Got an error in the CallbackView:",
                exc_info=error,
            )
            return self._display_login_error("Authentication failed")

        state_entry = self._pop_state_entry(request, authorization_response["state"])
        if state_entry is None:
            # This message is intended to be shown to the user, the missing session information is not
            # an indication of an attack by itself.
            return self._display_login_error(
                "Failed to get session info necessary to complete authentication in the session.\n"
                "Make sure to enable cookies for this app before retrying"
            )

        try:
            tokens = oidc_client.exchange_code_for_access_token(
                code=authorization_response["code"],
                expected_nonce=state_entry["nonce"],
            )
        except OidcProviderError as error:
            logger.error(
                f"Failed to exchange code for access token in the CallbackView.\n"
                f"Error code {error.response.get('error')}, message:\n",
                f"Description: {error.response.get('error_description')}",
            )
            return self._display_login_error(error.response.get('error_description'))
        except OidcError as error:
            logger.error(
                f"Got an error in the CallbackView when exchanging code for access token:",
                exc_info=error,
            )
            return self._display_login_error("Authentication failed")

        login_with_oidc_backend(request, tokens)
        return redirect(state_entry["next_url"])


class LogoutView(View):
    # Only POST is allowed and CSRF protection is not disabled to avoid CSRF redirects
    # from signing the user out from this app and the OIDC identity provider.
    def post(self, request):
        try:
            id_token_hint = request.session[SESSION_TOKENS_SESSION_KEY]["id_token"]
        except KeyError:
            id_token_hint = None
        authenticated_with_oidc = is_user_authenticated_with_oidc(request)

        # `logout` also clears the session, so the session is read before calling `logout`.
        logout(request)

        # Skip the OIDC logout if the user didn't use the `OidcAuthBackend` to sign in
        if not authenticated_with_oidc:
            return redirect(settings.LOGOUT_REDIRECT_URL)

        oidc_client = get_oidc_client()
        logout_url = oidc_client.get_logout_url(id_token_hint)
        response = redirect(logout_url)
        add_never_cache_headers(response)
        return response
