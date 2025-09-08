from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import SuspiciousOperation

from ._common import logger
from ._user_sessions import sync_roles
from .apps import KsiOidcAppConfig
from .models import KsiOidcUser


class OidcAuthBackend(BaseBackend):
    """
    This backend is loosely based on the one from mozilla-django-oidc.

    This backend allows inactive users to authenticate with OIDC as well.
    """

    def __init__(self):
        # The app also calls this function, but only if it's in the INSTALLED_APPS list
        KsiOidcAppConfig.verify_correct_setup()

        super().__init__()
        self.user_model = get_user_model()

    def _find_existing_user(self, oidc_id_token_claims: dict):
        """
        Finds and returns an existing user stored in the database for the claims in `oidc_id_token_claims`.

        Raises a `SuspiciousOperation` error if there are multiple users with the same sub or email.
        """
        # The implementation is based on `filter_users_by_claims` in mozilla-django-oidc

        sub = oidc_id_token_claims["sub"]
        email = oidc_id_token_claims["email"]

        sub_matching_users = self.user_model.objects.filter(ksi_oidc_user__sub=sub)
        if len(sub_matching_users) > 1:
            # This should never be possible, because KsiOidcUser.user is a one-to-one field.
            logger.error(
                f"Found {len(sub_matching_users)} existing users matching the sub {sub}"
            )
            raise SuspiciousOperation(
                "Multiple accounts with the same sub found in Django database"
            )
        if len(sub_matching_users) == 1:
            user = sub_matching_users[0]
            logger.debug(
                f"Found existing user with Django id {user.id} matching the sub {sub}"
            )
            return user

        email_matching_users = self.user_model.objects.filter(email__iexact=email)
        if len(email_matching_users) > 1:
            logger.warning(
                f"Found {len(email_matching_users)} existing users matching the email {email}"
            )
            raise SuspiciousOperation(
                "Multiple accounts with the same email found in Django database"
            )
        if len(email_matching_users) == 1:
            user = email_matching_users[0]
            logger.debug(
                f"Found existing user with Django id {user.id} matching the email {email}"
            )
            if hasattr(user, "ksi_oidc_user"):
                logger.error(
                    f"A Django user was found for the OIDC account with sub: {sub} and email: {email}, "
                    f"but it has been previously linked to the OIDC account with sub: {user.ksi_oidc_user.sub}."
                )
                raise SuspiciousOperation(
                    "An account with this email but a different linked provider acount found in Django database."
                )
            return user

        return None

    def _create_user(self, id_token_claims: dict):
        """
        Creates and returns a new user object with the username and email from `id_token_claims`.

        This method does not call .save() on the user object.
        The user object created by this function should be passed as an argument to `_update_user`.
        """

        email = id_token_claims.get("email")
        username = id_token_claims.get("preferred_username")
        user = self.user_model.objects.create_user(username, email=email)
        return user

    @staticmethod
    def _update_user(user, id_token_claims, access_token_claims):
        user.first_name = id_token_claims.get("given_name", "")
        user.last_name = id_token_claims.get("family_name", "")
        user.email = id_token_claims.get("email")
        user.save()

        try:
            user.ksi_oidc_user.sub = id_token_claims["sub"]
            user.ksi_oidc_user.save()
        except get_user_model().ksi_oidc_user.RelatedObjectDoesNotExist:
            KsiOidcUser.objects.create(user=user, sub=id_token_claims["sub"])

        sync_roles(user, access_token_claims)

    def authenticate(
        self, request, oidc_id_token_claims=None, oidc_access_token_claims=None
    ):
        if oidc_id_token_claims is None or oidc_access_token_claims is None:
            return None

        user = self._find_existing_user(oidc_id_token_claims)
        if user is None:
            user = self._create_user(oidc_id_token_claims)

        self._update_user(user, oidc_id_token_claims, oidc_access_token_claims)
        return user

    def get_user(self, user_id):
        try:
            return self.user_model.objects.get(pk=user_id)
        except self.user_model.DoesNotExist:
            return None
