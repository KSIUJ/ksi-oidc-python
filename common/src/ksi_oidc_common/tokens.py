from dataclasses import dataclass
from datetime import datetime, UTC, timedelta
from typing import Self

from oic.extension.token import JWTToken
from oic.oic import AccessTokenResponse


@dataclass
class Tokens:
    access_token: str
    refresh_token: str
    id_token: str

    id_token_claims: dict
    access_token_roles: list[str]

    access_expires_at: datetime
    refresh_expires_at: datetime

    raw_response: AccessTokenResponse

    @staticmethod
    def from_response(
        response: AccessTokenResponse,
        access_token_roles: list[str],
        request_time: datetime = datetime.now(UTC),
    ) -> "Tokens":
        access_expires_in = response.get("expires_in", None)
        if access_expires_in is None:
            raise ValueError("Missing expires_in in access token response")
        access_expires_at = request_time + timedelta(seconds=access_expires_in)

        refresh_expires_in = response.get("refresh_expires_in", None)
        if refresh_expires_in is None:
            raise ValueError("Missing refresh_expires_in in access token response")
        refresh_expires_at = request_time + timedelta(seconds=refresh_expires_in)

        return Tokens(
            access_token=response["access_token"],
            refresh_token=response["refresh_token"],
            id_token=response["id_token_jwt"],

            id_token_claims=response["id_token"],
            access_token_roles=access_token_roles,

            access_expires_at=access_expires_at,
            refresh_expires_at=refresh_expires_at,

            raw_response=response,
        )
