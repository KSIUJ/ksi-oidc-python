from typing import Optional

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import Group, User
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.http import HttpRequest

from ksi_oidc_common.tokens import Tokens, AccessTokenClaims

from ._common import get_oidc_client, logger
from ._consts import SESSION_TOKENS_SESSION_KEY


def sync_roles(user: User, access_token_claims: AccessTokenClaims):
    """
    Transform roles obtained from keycloak into Django Groups and
    add them to the user. Note that any role not passed via Keycloak
    will be removed from the user.
    """

    def user_has_role(setting_name: str) -> Optional[bool]:
        setting_value = getattr(settings, setting_name, None)
        if setting_value is None:
            return None
        if (
            not isinstance(setting_value, tuple)
            or len(setting_value) != 2
            or setting_value[0] not in ("realm", "client")
            or not isinstance(setting_value[1], str)
        ):
            raise ImproperlyConfigured(
                f"The {setting_name} setting must be a tuple ('realm', str) or ('client', str)"
            )

        (kind, name) = setting_value
        if kind == "realm":
            return name in access_token_claims.realm_roles
        if kind == "client":
            return name in access_token_claims.client_roles
        raise ValueError(f"Invalid role type: {kind}")

    has_staff_role = user_has_role("OIDC_STAFF_ROLE")
    if has_staff_role is not None:
        user.is_staff = has_staff_role
    has_superuser_role = user_has_role("OIDC_SUPERUSER_ROLE")
    if has_superuser_role is not None:
        user.is_superuser = has_superuser_role

    user.save()

    if getattr(settings, "OIDC_SYNC_ROLES_AS_GROUPS", False):
        with transaction.atomic():
            role_names = [
                f"oidc.realm.{role}" for role in access_token_claims.realm_roles
            ] + [f"oidc.client.{role}" for role in access_token_claims.client_roles]

            oidc_groups = [
                Group.objects.get_or_create(name=name)[0] for name in role_names
            ]
            non_oidc_groups = list(user.groups.exclude(name__startswith="oidc."))

            user.groups.set(oidc_groups + non_oidc_groups)


def update_session(request: HttpRequest, tokens: Tokens):
    # TODO: Verify that the id token is for the signed user
    # TODO: Verify sid when back-channel logout is implemented

    # The "refresh_expires_in" is the remaining length of the OIDC client session.
    # When a refresh token is used to get a new access token, a new refresh token is usually granted too,
    # possibly with a different expiration time, so the session expiry should also be updated then.
    request.session.set_expiry(tokens.refresh_expires_at)

    request.session[SESSION_TOKENS_SESSION_KEY] = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "id_token": tokens.id_token,
        "access_expires_at": tokens.access_expires_at.isoformat(),
    }


def refresh_access_token(request: HttpRequest, refresh_token: str):
    oidc_client = get_oidc_client()
    tokens = oidc_client.refresh_access_token(refresh_token)
    update_session(request, tokens)
    sync_roles(request.user, tokens.access_token_claims)


def login_with_oidc_backend(request: HttpRequest, tokens: Tokens):
    user = authenticate(
        request,
        oidc_id_token_claims=tokens.id_token_claims,
        oidc_access_token_claims=tokens.access_token_claims,
    )
    if user is None:
        raise ImproperlyConfigured(
            "Failed to authenticate user. Is the `OidcAuthBackend` enabled?"
        )

    login(request, user)
    update_session(request, tokens)
    logger.info("User %s signed in using OIDC", user.get_username())
