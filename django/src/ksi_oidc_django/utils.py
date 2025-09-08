from datetime import datetime, timedelta, UTC

from django.contrib.auth import get_backends, BACKEND_SESSION_KEY, logout
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.cache import add_never_cache_headers
from django.utils.crypto import get_random_string
from django.utils.module_loading import import_string

from ksi_oidc_common.errors import OidcProviderError

from ._common import logger, get_oidc_client
from ._consts import (
    STATES_SESSION_KEY,
    SESSION_TOKENS_SESSION_KEY,
    MIDDLEWARE_APPLIED_KEY,
    MIDDLEWARE_APPLIED_VALUE,
)
from ._user_sessions import refresh_access_token
from .backends import OidcAuthBackend


def is_oidc_auth_backend_enabled() -> bool:
    # The list returned from `get_backends()` contains INSTANCES of the backends.
    return any(isinstance(backend, OidcAuthBackend) for backend in get_backends())


def is_user_authenticated_with_oidc(request: HttpRequest) -> bool:
    # This function is based on mozilla-django-oidc:
    # https://github.com/mozilla/mozilla-django-oidc/blob/774b140b9311c6c874c199bfdb266e51f36740a7/mozilla_django_oidc/middleware.py#L104C9-L109C82

    if not request.user.is_authenticated:
        return False

    try:
        backend_session = request.session[BACKEND_SESSION_KEY]
    except KeyError:
        return False

    try:
        auth_backend = import_string(backend_session)
    except ImportError:
        logger.warning(
            "Failed to import auth backend specified in the session at BACKEND_SESSION_KEY. Signing the user out",
            exc_info=True,
        )
        logout(request)
        return False

    # The imported auth_backend is a CLASS TYPE, not an INSTANCE of it.
    return issubclass(auth_backend, OidcAuthBackend)


def ensure_middleware_was_applied(request: HttpRequest):
    """
    This functions verifies that the `OidcAuthMiddleware` was applied to the request
    and raises an `ImproperlyConfigured` exception if it wasn't.
    """

    # `OidcAuthMiddleware` checks if the `OidcAuthBackend` is enabled and raises
    # `MiddlewareNotUsed` if it's not, so we should not run the check in this case.
    if not is_oidc_auth_backend_enabled():
        return

    if getattr(request, MIDDLEWARE_APPLIED_KEY, None) is not MIDDLEWARE_APPLIED_VALUE:
        raise ImproperlyConfigured(
            "The `OidcAuthMiddleware` was not applied to this request. "
            "This indicates a configuration error, the `OidcAuthMiddleware` is crutial for security."
        )


def redirect_to_oidc_login(
    request: HttpRequest, next_url: str, prompt_none: bool = False
) -> HttpResponse:
    """
    Redirects to the OIDC login page if the `OidcAuthBackend` is enabled or to the `LOGIN_URL` otherwise.

    The caller must ensure that the `next_url` is safe.
    """

    if next_url is None:
        raise ValueError("next_url must be provided")

    # If the `OidcAuthBackend` is not enabled, redirect to `LOGIN_URL` instead of redirecting to the OIDC provider.
    #
    # Note: This could result in an infinite loop if the view at `LOGIN_URL` uses `redirect_to_oidc_login`
    #       when the `OidcAuthBackend` is not enabled.
    #       The default `OidcLoginView` calls `redirect_to_oidc_login` only if the `OidcAuthBackend` is enabled,
    #       so this is not a problem when the `LOGIN_URL` is (a subclass of) `OidcAuthBackend`.
    if not is_oidc_auth_backend_enabled():
        if prompt_none:
            raise ImproperlyConfigured(
                "`prompt_none = True` in `redirect_to_oidc_login` is not supported when the `OidcAuthBackend` is not enabled"
            )

        return redirect_to_login(next_url)

    ensure_middleware_was_applied(request)

    oidc_client = get_oidc_client()

    state = get_random_string(32)
    nonce = get_random_string(32)

    states = request.session.get(STATES_SESSION_KEY, {})
    # TODO: mozilla-django-oidc limits the number of stored states, we could do it too
    states[state] = {
        "nonce": nonce,
        "next_url": next_url,
    }
    request.session[STATES_SESSION_KEY] = states
    # Previously, the session was not saved when modifying nested dicts in the session object.
    # This should no longer be a problem, because now the key STATES_SESSION_KEY always gets reassigned,
    # but explicitly marking the session as modified doesn't hurt:
    # See https://docs.djangoproject.com/en/5.2/topics/http/sessions/#when-sessions-are-saved
    request.session.modified = True

    authentication_url = oidc_client.get_authentication_url(nonce, state, prompt_none)
    response = redirect(authentication_url)
    add_never_cache_headers(response)
    return response


def refresh_oidc_auth_session(request: HttpRequest):
    """
    Verify the validity of the access token and refresh it if it has expired.
    Logs the user out if refreshing the access token fails.

    `OidcAuthMiddleware` calls this function for all requests.
    """

    # Set a flag in the request object indicating that the middleware was applied.
    # Views provided in this package will use this flag to make sure that the app is
    # configured properly by callling the `_common.ensure_middleware_was_applied` function.
    setattr(request, MIDDLEWARE_APPLIED_KEY, MIDDLEWARE_APPLIED_VALUE)

    if not is_user_authenticated_with_oidc(request):
        return

    try:
        session_tokens = request.session[SESSION_TOKENS_SESSION_KEY]
    except KeyError:
        logger.error(
            "Failed to access SESSION_TOKENS_SESSION_KEY for a user. Signing the user out."
        )
        logout(request)
        return

    if datetime.fromisoformat(session_tokens["access_expires_at"]) > datetime.now(
        UTC
    ) + timedelta(seconds=5):
        # The access token is still valid and will be valid for at least 5 more seconds
        return

    logger.debug(
        "The access token for user %s has expired, refreshing", request.user.username
    )
    try:
        refresh_access_token(request, session_tokens["refresh_token"])
        logger.info("Refreshed expired access token for user %s", request.user.username)
    except Exception as error:
        if (
            isinstance(error, OidcProviderError)
            and error.response["error"] == "invalid_grant"
        ):
            # This is an expected case, there is no need to raise an error here
            logger.info("Refresh token for user %s has expired, signing them out")
            logout(request)
            return

        # If anything went wrong, the user should be signed out,
        # since they no longer have a valid access token.
        logger.error(
            "Failed to refresh access token for user %s, signing them out",
            request.user.username,
            exc_info=True,
        )
        logout(request)
        raise
