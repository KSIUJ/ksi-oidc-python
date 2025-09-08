from django.core.management import BaseCommand, CommandError
from ksi_oidc_django.models import KsiOidcClientConfig
from .._input_utils import prompt_yes_no


class Command(BaseCommand):
    def handle(self, *args, **options):
        if not prompt_yes_no("Reset OIDC configuration?"):
            self.stdout.write("Nothing done")
            return

        KsiOidcClientConfig.get_solo().reset()
        self.stdout.write("OIDC conifiguration reset")

