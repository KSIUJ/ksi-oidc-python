import logging
from typing import Optional
from urllib.parse import urljoin

from django.conf import settings
from django.http import HttpRequest
from django.urls import reverse

from ksi_oidc_common.client import OidcClient
from oic.exception import ImproperlyConfigured

logger = logging.getLogger('ksi_oidc_django')


_cached_oidc_client: Optional[OidcClient] = None


def get_oidc_client() -> OidcClient:
    # Avoid circular imports
    from .models import KsiOidcClientConfig

    global _cached_oidc_client

    if _cached_oidc_client is None:
        client_config = KsiOidcClientConfig.get_solo()

        if client_config.issuer is None:
            raise ImproperlyConfigured(
                "The OIDC issuer URL has not been set.\n"
                "Use the 'manage.py oidc_set_issuer' command to set it."
            )

        if client_config.client_id is None or client_config.client_secret is None:
            raise ImproperlyConfigured(
                "The OIDC client credentials have not been provided.\n"
                "Use the 'manage.py oidc_init_dynamic' or 'manage.py oidc_init_static' commands to configure the client."
            )
            return

        # Do not set _cached_oidc_client directly to avoid leaving it in a partially initialized state if an exception is raised
        client = OidcClient.load(
            issuer = client_config.issuer,
            callback_uri = urljoin(settings.OIDC_APP_BASE_URL, reverse("ksi_oidc_callback")),
            post_logout_redirect_uri = urljoin(settings.OIDC_APP_BASE_URL, settings.LOGOUT_REDIRECT_URL),
        )
        client.set_credentials(
            client_id = client_config.client_id,
            client_secret = client_config.client_secret,
        )
        _cached_oidc_client = client

    return _cached_oidc_client
