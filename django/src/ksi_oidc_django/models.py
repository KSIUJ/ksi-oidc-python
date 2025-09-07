from django.conf import settings
from django.db import models

class KsiOidcUser(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='ksi_oidc_user',
    )
    sub = models.CharField(unique=True)
