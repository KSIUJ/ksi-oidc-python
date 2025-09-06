import logging
from json import JSONDecodeError
from typing import Type, TypeVar, Optional, Self

import requests
from oic.exception import MessageException
from oic.extension.token import JWTToken
from oic.oauth2.message import SchemeError, ErrorResponse
from oic.oic import EndSessionRequest
from oic.oic.message import Message, ProviderConfigurationResponse, AuthorizationRequest, AuthorizationResponse, \
    AuthorizationErrorResponse, AccessTokenResponse, AccessTokenRequest, TokenErrorResponse
from oic.utils.keyio import KeyJar

from .errors import OidcProviderError, OidcValidationError, OidcRequestError
from .tokens import Tokens

logger = logging.getLogger("ksi_oidc_common")

TMessage = TypeVar('TMessage', bound=Message)


class OidcClient:
    """
    A stateless OpenID Connect client based on the `pyoidc` library.

    Create new instances using the `OidcClient.load()` method.
    """

    oidc_scope = "openid email"

    provider_configuration: ProviderConfigurationResponse

    @classmethod
    def load(cls, client_id: str, client_secret: str, issuer: str, **kwargs) -> Self:
        """
        Creates a new `OidcClient` instance and fetches the OIDC Provider configuration
        from <issuer>/.well-known/openid-configuration.
        """

        client = cls(
            client_id=client_id,
            client_secret=client_secret,
            **kwargs,
        )
        client._load(issuer)
        return client

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        # kwargs can be used when subclassing `OidcClient`
        **_kwargs,
    ):
        """
        This constructor should not be called directly,
        use the OidcClient.load() method instead.
        """

        self.keyjar = KeyJar()
        # The provider configuration will be stored in `_load()`,
        # so access to the uninitialized `provider_configuration` attribute
        # is unlikely.
        self.provider_configuration = None # type: ignore

        self.client_id = client_id
        self.client_secret = client_secret

    def _handle_response(
        self,
        response: requests.Response,
        success_response_type: Type[TMessage],
        error_response_type: Optional[Type[ErrorResponse]],
        ignore_scheme_error: bool = False,
    ) -> TMessage:
        if not response.ok and error_response_type is not None:
            try:
                error_message = error_response_type()
                error_message.from_dict(response.json())
                error_message.verify(keyjar=self.keyjar)
                raise OidcProviderError(error_message)
            except (MessageException, JSONDecodeError):
                # These errors should lead to calling raise_for_status()
                # Other errors are unexpected and are passed to the caller.
                pass

        response.raise_for_status()

        message = success_response_type()
        message.from_dict(response.json())

        if ignore_scheme_error:
            try:
                message.verify(keyjar=self.keyjar)
            except SchemeError as error:
                logger.error("Got SchemeError when verifying response from OIDC Provider: %s", error)
                pass
        else:
            message.verify(keyjar=self.keyjar)

        return message

    def _handle_callback_response(
        self,
        query_params: dict,
        success_response_type: Type[TMessage],
        error_response_type: Type[ErrorResponse],
    ) -> TMessage:
        if 'error' in query_params:
            try:
                error_response = error_response_type()
                error_response.from_dict(query_params)
                error_response.verify(keyjar=self.keyjar)
                raise OidcProviderError(error_response)
            except (MessageException, KeyError):
                raise OidcRequestError("Received an invalid error response from the OIDC Provider")

        try:
            response = success_response_type()
            response.from_dict(query_params)
            response.verify(keyjar=self.keyjar)
            return response
        except (MessageException, KeyError):
            raise OidcRequestError("Received an invalid response from the OIDC Provider")

    def _get_request(
        self,
        success_response_type: Type[TMessage],
        error_response_type: Optional[Type[ErrorResponse]],
        url,
        ignore_scheme_error: bool = False,
    ) -> TMessage:
        response = requests.get(url)
        return OidcClient._handle_response(self, response, success_response_type, error_response_type, ignore_scheme_error)

    def _authenticated_post_request(
        self,
        success_response_type: Type[TMessage],
        error_response_type: Optional[Type[ErrorResponse]],
        url: str,
        request_body: Message,
    ) -> TMessage:
        response = requests.post(url, data=request_body.to_dict(), auth=(self.client_id, self.client_secret))
        return self._handle_response(response, success_response_type, error_response_type)

    def _create_redirect_url(self, base_url: str, message: TMessage) -> str:
        message.verify(keyjar=self.keyjar)
        return base_url + "?" + message.to_urlencoded()

    def _load_jwks_keys(self):
        self.keyjar.add(self.provider_configuration["issuer"], self.provider_configuration['jwks_uri'])

    def _load(self, issuer: str):
        logger.debug("Loading OIDC Provider configuration")

        config_url = issuer
        if not config_url.endswith("/"):
            config_url += "/"
        config_url += ".well-known/openid-configuration"

        # TODO: ignore_scheme_error
        configuration = self._get_request(
            ProviderConfigurationResponse,
            None,
            config_url,
            ignore_scheme_error=True,
        )
        if configuration.get("issuer") != issuer:
            raise OidcValidationError(
                f"The issuer returned by the OIDC Provider:\n{configuration.get("issuer")}\n"
                f"does not match the one configured:\n${issuer}"
            )
        self.provider_configuration = configuration
        self._load_jwks_keys()
        logger.info("Fetched OIDC Provider configuration from %s", config_url)

    def _get_roles_from_access_token(self, access_token: str) -> list[str]:
        jwt = JWTToken(
            typ='A', # Access token
            keyjar=self.keyjar,
        )
        result = jwt.unpack(access_token)
        return result.get("realm_access", {}).get("roles", [])

    def _parse_tokens_response(self, response: AccessTokenResponse) -> Tokens:
        access_token_roles = self._get_roles_from_access_token(response["access_token"])
        return Tokens.from_response(response, access_token_roles)

    def get_authentication_url(self, redirect_uri: str, nonce: str, state: str, prompt_none: bool) -> str:
        request_args = {
            'client_id': self.client_id,
            'response_type': "code",
            'scope': self.oidc_scope,
            'nonce': nonce,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        if prompt_none:
            request_args['prompt'] = 'none'

        return self._create_redirect_url(
            self.provider_configuration['authorization_endpoint'],
            AuthorizationRequest(**request_args),
        )

    def get_logout_url(self, post_logout_redirect_uri: str, id_token_hint: Optional[str]) -> str:
        request_args = {
            "id_token_hint": id_token_hint,
            "post_logout_redirect_uri": post_logout_redirect_uri,
        }
        return self._create_redirect_url(
            self.provider_configuration['end_session_endpoint'],
            EndSessionRequest(**request_args),
        )

    def parse_authorization_callback_response(self, query_params: dict) -> AuthorizationResponse:
        return self._handle_callback_response(query_params, AuthorizationResponse, AuthorizationErrorResponse)

    def exchange_code_for_access_token(
        self,
        redirect_uri: str,
        code: str,
        expected_nonce: str,
    ) -> Tokens:
        # TODO: Add PKCE verification

        request_args = {
            'grant_type': 'authorization_code',
            'code': code,
            # The OIDC Provider verifies that this `redirect_uri` is the same as the one provided
            # in the `AuthorizationRequest`.
            # It will not be used for any new redirect.
            'redirect_uri': redirect_uri,
        }
        response = self._authenticated_post_request(
            AccessTokenResponse,
            TokenErrorResponse,
            self.provider_configuration['token_endpoint'],
            AccessTokenRequest(**request_args),
        )

        if expected_nonce != response["id_token"]["nonce"]:
            raise OidcValidationError("The authentication request has been tampered with, cannot continue")

        return self._parse_tokens_response(response)

    def refresh_access_token(self, refresh_token: str) -> Tokens:
        # TODO: Add PKCE verification (if it is even used here)

        request_args = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }
        response = self._authenticated_post_request(
            AccessTokenResponse,
            TokenErrorResponse,
            self.provider_configuration['token_endpoint'],
            AccessTokenRequest(**request_args),
        )
        return self._parse_tokens_response(response)
