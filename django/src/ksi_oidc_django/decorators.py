from datetime import timedelta
from functools import wraps

from django.conf import settings

from ._consts import SKIP_SSO_CHECK_COOKIE
from .utils import redirect_to_oidc_login, is_oidc_auth_backend_enabled, ensure_middleware_was_applied


def ksi_oidc_check_sso(function):
    """
    This view decorator redirects unauthenticated users to the OIDC authentication endpoint with `prompt=none`,
    to check if they have an active SSO session.

    After this check, a cookie is set to prevent it from being performed again.
    The max age of the cookie is configurable via the `OIDC_AUTH_SSO_CHECK_COOLDOWN_SECONDS` setting.
    """

    def should_run_check(request):
        if request.user.is_authenticated:
            return False

        if not is_oidc_auth_backend_enabled():
            return False

        if SKIP_SSO_CHECK_COOKIE in request.COOKIES:
            return False

        return True

    @wraps(function)
    def wrap(request, *args, **kwargs):
        ensure_middleware_was_applied(request)

        if should_run_check(request):
            response = redirect_to_oidc_login(request, request.get_full_path(), prompt_none=True)
            cooldown_seconds = getattr(settings, 'OIDC_AUTH_SSO_CHECK_COOLDOWN_SECONDS', 300)
            response.set_cookie(SKIP_SSO_CHECK_COOKIE, max_age=timedelta(seconds=cooldown_seconds))
            return response

        return function(request, *args, **kwargs)

    return wrap


def ksi_oidc_login_required(function):
    """
    This view decorator verifies that the user is authenticated and if not,
    redirects directly to the OIDC login page if the `OidcAuthBackend` is enabled
    or to the `LOGIN_URL` otherwise.

    Note: The user does not need to be signed in using the `OidcAuthBackend`
    to access views decorated with `ksi_oidc_login_required`, users authenticated
    with other packends (e.g. Django's `ModelBackend`) will be allowed too.

    This is similar to the `@login_required` decorator from `django.contrib.auth`,
    but it can redirect directly to the OIDC login page, without redirecting to the `LoginView` first.
    """

    @wraps(function)
    def wrap(request, *args, **kwargs):
        ensure_middleware_was_applied(request)

        if not request.user.is_authenticated:
            return redirect_to_oidc_login(request, request.get_full_path())

        return function(request, *args, **kwargs)

    return wrap
