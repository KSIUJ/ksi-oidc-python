from django.core.management import BaseCommand, CommandError
from ksi_oidc_common.client import OidcClient
from ksi_oidc_django.models import KsiOidcClientConfig


class Command(BaseCommand):
    def handle(self, *args, **options):
        config = KsiOidcClientConfig.get_solo()
        if config.issuer is not None:
            self.stdout.write(f"The OIDC issuer URI is currently set to: {config.issuer}")
        new_issuer = input("Enter the new issuer URI:\n").strip()
        if new_issuer.endswith("/"):
            new_issuer = new_issuer[:-1]

        if new_issuer == "":
            raise CommandError("The issuer URI cannot be empty. Use the 'manage.py oidc_reset' command to reset all configuration.")

        try:
            client = OidcClient.load(issuer = new_issuer)
        except Exception as e:
            raise CommandError(f"Failed to load the OIDC Provider configuration from {new_issuer}/.well-known/openid-configuration: {e}")

        config.issuer = new_issuer
        config.save()
        self.stdout.write(f"Successfuly set the issuer URI to: {config.issuer}")
