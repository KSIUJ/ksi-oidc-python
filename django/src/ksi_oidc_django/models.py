from django.conf import settings
from django.db import models
from solo.models import SingletonModel


class KsiOidcUser(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="ksi_oidc_user",
    )
    # The max length is specified in the OpenID Connect Core spec:
    # https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    sub = models.CharField(unique=True, max_length=255)


class KsiOidcClientConfig(SingletonModel):
    issuer = models.URLField(null=True)

    client_id = models.CharField(null=True)
    client_secret = models.CharField(null=True)

    """
    Endpoint for reconfiguring the OIDC Provider.
    It is not used for initial registration. 
    """
    configuration_endpoint = models.URLField(null=True)
    registration_token = models.CharField(null=True)

    def save(self, **kwargs):
        if (self.configuration_endpoint is None) != (self.registration_token is None):
            raise ValueError(
                "KsiOidcProviderConfig: Both configuration_endpoint and registration_token must be set or unset together"
            )

        if (self.client_id is None) != (self.client_secret is None):
            raise ValueError(
                "KsiOidcProviderConfig: Both client_id and client_secret must be set or unset together"
            )

        if (self.configuration_endpoint is not None) and (self.client_id is None):
            raise ValueError(
                "KsiOidcProviderConfig: client_id must be set when configuration_endpoint is set"
            )

        if (self.client_id is not None) and (self.issuer is None):
            raise ValueError(
                "KsiOidcProviderConfig: issuer must be set when client_id is set"
            )

        super().save(**kwargs)
