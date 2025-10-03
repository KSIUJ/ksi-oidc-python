import logging
from typing import Optional

from ksi_oidc_common.client import OidcClient
from oic.exception import ImproperlyConfigured

logger = logging.getLogger("ksi_oidc_fastapi")


def fetch_unauthenticated_client(client_config) -> OidcClient:
    if client_config.issuer is None:
        raise ImproperlyConfigured(
            "The OIDC issuer URL has not been set.\n"
            "Change the .env file"
        )

    login_requested_scopes = ["email", "profile", "roles"]


    return OidcClient.load(
        issuer=client_config.issuer,
        login_requested_scopes=login_requested_scopes,
        offline_requested_scopes=["offline_access"],
        home_uri=client_config.home_uri,
        callback_uri=client_config.callback_uri,
        post_logout_redirect_uri=client_config.post_logout_redirect_uri
    )


_cached_oidc_client: Optional[OidcClient] = None


def get_oidc_client() -> OidcClient:
    from .models import OidcConf

    global _cached_oidc_client

    if _cached_oidc_client is None:
        client_config = OidcConf

        if client_config.client_id is None or client_config.client_secret is None:
            raise ImproperlyConfigured(
                "The OIDC client credentials have not been provided.\n"
                "Change the .env files"
            )

        client = fetch_unauthenticated_client(client_config)
        client.set_credentials(
            client_id=client_config.client_id,
            client_secret=client_config.client_secret,
        )
        _cached_oidc_client = client

    return _cached_oidc_client

