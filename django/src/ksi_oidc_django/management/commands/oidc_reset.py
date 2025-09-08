from django.core.management import BaseCommand
from ksi_oidc_django.models import KsiOidcClientConfig
from .._input_utils import prompt_yes_no


class Command(BaseCommand):
    help = "Reset the OIDC client configuration."

    def handle(self, *args, **options):
        config = KsiOidcClientConfig.get_solo()

        if config.client_id is None:
            self.stdout.write("OIDC client is not configured")
        elif not prompt_yes_no("Reset OIDC client configuration?"):
            self.stdout.write("Exiting, nothing changed.")
            return

        config.client_id = None
        config.client_secret = None
        config.configuration_endpoint = None
        config.registration_token = None

        if config.issuer is None:
            self.stdout.write("Issuer URI is not configured, exiting.")
            config.save()
            return

        self.stdout.write(
            f"The issuer URI is currently set to:\n{config.issuer}",
        )
        if prompt_yes_no("Reset issuer URI?"):
            config.issuer = None

        config.save()
        self.stdout.write("Stored configuration, done.")
