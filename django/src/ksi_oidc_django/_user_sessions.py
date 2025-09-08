from datetime import datetime, UTC, timedelta

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import Group, User
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.http import HttpRequest

from ksi_oidc_common.tokens import Tokens

from ._common import get_oidc_client, logger
from ._consts import SESSION_TOKENS_SESSION_KEY


def sync_roles(user: User, roles: list[str]):
    """
    Transform roles obtained from keycloak into Django Groups and
    add them to the user. Note that any role not passed via Keycloak
    will be removed from the user.
    """

    if getattr(settings, 'OIDC_STAFF_ROLE', None) is not None:
        user.is_staff = settings.OIDC_STAFF_ROLE in roles
    if getattr(settings, 'OIDC_SUPERUSER_ROLE', None) is not None:
        user.is_superuser = settings.OIDC_SUPERUSER_ROLE in roles
    user.save()

    if getattr(settings, 'OIDC_SYNC_ROLES_AS_GROUPS', False):
        with transaction.atomic():
            user.groups.clear()
            for role in roles:
                group, _ = Group.objects.get_or_create(name=role)
                group.user_set.add(user)


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
    sync_roles(request.user, tokens.access_token_roles)


def login_with_oidc_backend(request: HttpRequest, tokens: Tokens):
    user = authenticate(request, oidc_id_token_claims = tokens.id_token_claims, oidc_roles = tokens.access_token_roles)
    if user is None:
        raise ImproperlyConfigured("Failed to authenticate user. Is the `OidcAuthBackend` enabled?")

    login(request, user)
    update_session(request, tokens)
    logger.info("User %s signed in using OIDC", user.get_username())
