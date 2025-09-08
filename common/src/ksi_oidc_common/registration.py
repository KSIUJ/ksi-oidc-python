from oic.oic import RegistrationResponse


class RegistrationResult:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        registration_access_token: str,
        registration_client_uri: str,
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
