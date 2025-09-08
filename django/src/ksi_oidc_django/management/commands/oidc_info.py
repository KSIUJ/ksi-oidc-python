from django.core.management import BaseCommand, CommandError
from ksi_oidc_common.client import OidcClient
from ksi_oidc_django.models import KsiOidcClientConfig
from ksi_oidc_django._common import fetch_unauthenticated_client


class Command(BaseCommand):
    def handle(self, *args, **options):
        config = KsiOidcClientConfig.get_solo()

        self.stdout.write(f"OIDC configuration:")

        if config.issuer is None:
            self.stdout.write(f"The issuer URI is not set.")
            self.stdout.write(f"Use the 'manage.py oidc_set_issuer' command to set it.")
            return

        self.stdout.write(f"Issuer URI:        \t{config.issuer}")

        if config.client_id is None:
            self.stdout.write(f"The client ID is not set.")
            self.stdout.write(f"Use the 'manage.py oidc_init_dynamic' or 'manage.py oidc_init_static' commands to initialize the client.")
            return

        self.stdout.write(f"Client ID:         \t{config.client_id}")
        self.stdout.write(f"Client Secret:     \t***")

        if config.registration_token is None:
            self.stdout.write(f"Dynamic registration is disabled.")
            self.stdout.write(f"Use the 'manage.py oidc_init_dynamic' command to enable it.")
            return

        self.stdout.write(f"Dynamic registration is enabled.")
        self.stdout.write(f"Config ednpoint:   \t{config.configuration_endpoint}")
        self.stdout.write(f"Registration token:\t***")

        client = fetch_unauthenticated_client(config)
        client.get_registration_info(config.registration_token, config.configuration_endpoint)
        self.stdout.write(f"The dynamic registration endpoint and token are valid.")


