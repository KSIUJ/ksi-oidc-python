from django.core.management.base import BaseCommand, CommandError
from ksi_oidc_django.models import KsiOidcClientConfig
from .._input_utils import prompt_non_empty, prompt_yes_no


class Command(BaseCommand):
    help = "Register a new OIDC client using a provided Client ID and Client Secret."

    def handle(self, *args, **options):
        config = KsiOidcClientConfig.get_solo()
        if config.issuer is None:
            raise CommandError(
                "The OIDC issuer URI is not configured. "
                "Use the 'manage.py oidc_set_issuer' command to set it.",
            )

        require_confirmation = False

        if config.client_id is not None:
            self.stdout.write(
                "The Client ID and Client Secret are already set. "
                "Continue only if you want to replace them.",
            )
            require_confirmation = True

        if config.configuration_endpoint is not None:
            self.stdout.write(
                "The client is already registered using dynamic registration. "
                "If you continue, dynamic registration will be disabled."
            )
            require_confirmation = True

        if require_confirmation:
            if not prompt_yes_no("Continue?"):
                return

        client_id = prompt_non_empty("Enter the Client ID:")
        client_secret = prompt_non_empty("Enter the Client Secret:", secret=True)

        config.client_id = client_id
        config.client_secret = client_secret
        config.configuration_endpoint = None
        config.registration_token = None
        config.save()

        self.stdout.write("Stored the OIDC client credentials.")
