from oic.oauth2.message import ErrorResponse


class OidcProviderError(Exception):
    def __init__(self, response: ErrorResponse):
        super().__init__(
            f"Received an error response of type \"{response["error"]}\" from OIDC Provider:\n"
            f"{response.get('error_description', '')}",
        )
        self.response = response


class OidcRequestError(Exception):
    pass


class OidcValidationError(Exception):
    pass
