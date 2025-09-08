from django.core.management.base import BaseCommand, CommandError
from ksi_oidc_common.client import OidcClient
from ksi_oidc_common.errors import OidcProviderError
from ksi_oidc_common.registration import RegistrationResult
from ksi_oidc_django.models import KsiOidcClientConfig
from ksi_oidc_django._common import fetch_unauthenticated_client
from oic.oic.message import (
    ClientRegistrationErrorResponse,
)


class Command(BaseCommand):
    help = "Modify the OIDC client configuration using dynamic registration to use the Gutenberg default settings."

    def _update_config(
        self,
        info: RegistrationResult,
        config: KsiOidcClientConfig,
        client: OidcClient,
    ):
        if info.client_id is not None and info.client_id != config.client_id:
            raise CommandError(
                f"The registration ednpoint and token are for a different client: "
                f"{info.client_id}, not {config.client_id}"
            )

        if info.registration_access_token is not None:
            config.registration_token = info.registration_access_token
        if info.registration_client_uri is not None:
            config.configuration_endpoint = info.registration_client_uri
        if info.client_secret is not None:
            config.client_secret = info.client_secret

        config.save()

    def handle(self, *args, **options):
        config = KsiOidcClientConfig.get_solo()

        client = fetch_unauthenticated_client(config)

        try:
            info = client.modify_registration(
                config.registration_token,
                config.configuration_endpoint,
                config.client_id,
            )
            self._update_config(info, config, client)
        except Exception as e:
            if isinstance(e, OidcProviderError) and isinstance(
                e.response, ClientRegistrationErrorResponse
            ):
                info = RegistrationResult.from_error_response(e.response)
                self._update_config(info, config, client)
            raise CommandError(f"Failed to update the client configuration: {e}")

        self.stdout.write("Successfully updated the client configuration")
