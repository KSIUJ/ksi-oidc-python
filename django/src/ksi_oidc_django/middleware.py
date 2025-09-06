from django.core.exceptions import MiddlewareNotUsed

from ._common import logger
from .apps import KsiOidcAppConfig
from .utils import is_oidc_auth_backend_enabled, refresh_oidc_auth_session


class OidcAuthMiddleware:
    def __init__(self, get_response):
        # The app also calls this function, but only if it's in the INSTALLED_APPS list
        KsiOidcAppConfig.verify_correct_setup()

        if not is_oidc_auth_backend_enabled():
            logger.info("OidcAuthBackend is not enabled, OidcAuthMiddleware will not be used")
            raise MiddlewareNotUsed

        self.get_response = get_response

    def __call__(self, request):
        refresh_oidc_auth_session(request)

        return self.get_response(request)
