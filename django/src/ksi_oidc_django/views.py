from typing import Optional

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.views import LoginView as DjangoLoginView
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import redirect
from django.http import HttpRequest
from django.utils.cache import add_never_cache_headers
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.generic.base import View
from oic.oic import AuthorizationResponse

from ksi_oidc_common.errors import OidcProviderError

from ._common import logger, get_oidc_client
from ._consts import SESSION_TOKENS_SESSION_KEY, STATES_SESSION_KEY
from ._user_sessions import login_with_oidc_backend
from .utils import redirect_to_oidc_login, is_oidc_auth_backend_enabled, is_user_authenticated_with_oidc, \
    ensure_middleware_was_applied


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

    def __init__(self, fallback_view = None):
        if fallback_view is not None:
            # `staticmethod` is used to avoid binding the `self` argument from `OidcLoginView`.
            self.fallback_view = staticmethod(fallback_view)

    def _get_next_url(self, request):
        next_url = settings.LOGIN_REDIRECT_URL

        if 'next' in request.GET:
            next_url_is_valid = url_has_allowed_host_and_scheme(
                request.GET['next'],
                allowed_hosts=request.get_host(),
                require_https=request.is_secure(),
            )
            if next_url_is_valid:
                next_url = request.GET['next']
            else:
                logger.warning(f"Received an invalid next URL in the login request: {next_url}")

        return next_url

    def dispatch(self, request):
        if request.user.is_authenticated and request.method in ('GET', 'HEAD', 'POST'):
            response = redirect(self._get_next_url(request))
            add_never_cache_headers(response)
            return response

        if not is_oidc_auth_backend_enabled():
            # When the fallback view is used, requests with all methods are passed to it.
            # This might be needed if the fallback login view uses a HTML form with `method="post"`.
            return self.fallback_view(request)

        # There is no reason to allow submitting a POST request to the OIDC login endpoint.
        if request.method not in ('GET', 'HEAD'):
            return self.http_method_not_allowed()

        return redirect_to_oidc_login(request, self._get_next_url(request))



class CallbackView(View):
    def get(self, request: HttpRequest):
        if not is_oidc_auth_backend_enabled():
            # It's not this package that triggered the authentication,
            # and authenticating wouldn't be possible anyway without the backend.
            raise SuspiciousOperation("Received a response from the OIDC provider, but OidcAuthBackend is not enabled")

        ensure_middleware_was_applied(request)

        oidc_client = get_oidc_client()

        authorization_response: Optional[AuthorizationResponse] = None
        try:
            authorization_response = oidc_client.parse_authorization_callback_response(request.GET)
            state = authorization_response['state']
        except OidcProviderError as error:
            state = error.response["state"]
            if error.response["error"] in ("login_required", "interaction_required"):
                logger.debug(f"Received error {error.response["error"]} in the CallbackView")
            else:
                logger.warning(
                    f"Received error {error.response["error"]} in the CallbackView:\n"
                    f"{error.response.get('error_description', '')}",
                )
                # TODO: Handle errors

        try:
            state_entry = request.session.get(STATES_SESSION_KEY, {})[state]
        except KeyError:
            # This message is intended to be shown to the user, the missing session information is not
            # an indication of an attack by itself.
            raise SuspiciousOperation("Failed to find info necessary to complete authentication in the session")

        if authorization_response is not None:
            tokens = oidc_client.exchange_code_for_access_token(
                code=authorization_response["code"],
                expected_nonce=state_entry["nonce"],
            )
            login_with_oidc_backend(request, tokens)

        if STATES_SESSION_KEY in request.session:
            del request.session[STATES_SESSION_KEY][state]
            # Modifying an inner dict does not trigger the session save automatically,
            # setting `request.session.modified` makes sure that the session is saved.
            # See https://docs.djangoproject.com/en/5.2/topics/http/sessions/#when-sessions-are-saved
            request.session.modified = True

        response = redirect(state_entry['next_url'])
        add_never_cache_headers(response)
        return response


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
