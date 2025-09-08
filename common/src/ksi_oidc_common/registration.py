from typing import Optional
from oic.oic import RegistrationResponse, ClientRegistrationErrorResponse


class RegistrationResult:
    def __init__(
        self,
        client_id: Optional[str],
        client_secret: Optional[str],
        registration_access_token: Optional[str],
        registration_client_uri: Optional[str],
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.registration_access_token = registration_access_token
        self.registration_client_uri = registration_client_uri

    @staticmethod
    def from_response(response: RegistrationResponse) -> "RegistrationResult":
        return RegistrationResult(
            client_id=response["client_id"],
            client_secret=response["client_secret"],
            registration_access_token=response["registration_access_token"],
            registration_client_uri=response["registration_client_uri"],
        )

    @staticmethod
    def from_error_response(
        response: ClientRegistrationErrorResponse,
    ) -> "RegistrationResult":
        return RegistrationResult(
            client_id=response.get("client_id", None),
            client_secret=response.get("client_secret", None),
            registration_access_token=response.get("registration_access_token", None),
            registration_client_uri=response.get("registration_client_uri", None),
        )
