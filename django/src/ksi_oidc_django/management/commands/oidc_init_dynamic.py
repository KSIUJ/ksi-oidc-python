from django.core.management.base import BaseCommand, CommandError
from ksi_oidc_common.client import OidcClient
from ksi_oidc_django.models import KsiOidcClientConfig
from ksi_oidc_django._common import fetch_unauthenticated_client
from .._input_utils import prompt_non_empty, prompt_yes_no


class Command(BaseCommand):
    help = "Register a new OIDC client using dynamic registration or enable dynamic registration for an existing client."

    def _register(self, config: KsiOidcClientConfig, client: OidcClient):
        self.stdout.write("Registering a new client")
        registration_token = prompt_non_empty("Enter the initial registration access token:", secret=True)
        result = client.register(registration_token)

        config.client_id = result.client_id
        config.client_secret = result.client_secret
        config.configuration_endpoint = result.registration_client_uri
        config.registration_token = result.registration_access_token
        config.save()

        self.stdout.write(f"Successfully registered the client with Client ID: {config.client_id}")

    def _is_config_valid(self, config: KsiOidcClientConfig, client: OidcClient) -> bool:
        try:
            info = client.get_registration_info(config.registration_token, config.configuration_endpoint)
        except Exception as e:
            self.stdout.write(f"The configuration endpoint or token are invalid: {e}")
            return False

        if info.client_id != config.client_id:
            raise CommandError(
                f"The registration ednpoint and token are for a different client: "
                f"{info.client_id}, not {config.client_id}"
            )

        config.client_secret = info.client_secret

        return True

    def _update_config(self, config: KsiOidcClientConfig, client: OidcClient):
        if config.configuration_endpoint is None:
            self.stdout.write("Dynamic registration is not configured.")
            if not prompt_yes_no("Do you want to enable dynamic registration features?"):
                return

            self.stdout.write(
                "Enter the configuration endpoint specific to your client. It usually starts with:\n"
                f"{client.provider_configuration["registration_endpoint"]}",
            )
            self.stdout.write(
                "If you're using Keycloak as the provider, the endpoint is probably:\n"
                f"{client.provider_configuration['registration_endpoint']}/{config.client_id}",
            )
            config.configuration_endpoint = prompt_non_empty("Endpoint:")

        self.stdout.write(
            "Using the configuration endpoint: \n"
            f"{config.configuration_endpoint}",
        )

        if config.registration_token is not None:
            if self._is_config_valid(config, client):
                self.stdout.write("The existing dynamic registration token is valid, done.")
                self.stdout.write("Use the 'manage.py oidc_init_dynamic' command to update the client configuration.")
                config.save()
                return
            config.registration_token = None

        config.registration_token = prompt_non_empty("Enter the registration access token:", secret=True)

        if self._is_config_valid(config, client):
            self.stdout.write("The registration token is valid, done.")
            self.stdout.write("Use the 'manage.py oidc_init_dynamic' command to update the client configuration.")
            config.save()
            return

        raise CommandError("The registration access token is invalid.")

    def handle(self, *args, **options):
        config = KsiOidcClientConfig.get_solo()
        if config.issuer is None:
            raise CommandError(
                "The OIDC issuer URI is not configured. "
                "Use the 'manage.py oidc_set_issuer' command to set it.",
            )
        client = fetch_unauthenticated_client(config)

        if config.client_id is None:
            self.stdout.write("The Client ID is not set.")
            if prompt_yes_no("Have you already registered the client with the OIDC Provider?"):
                config.client_id = prompt_non_empty("Enter the Client ID:")

        if config.client_id is None:
            self._register(config, client)
            return

        self._update_config(config, client)
