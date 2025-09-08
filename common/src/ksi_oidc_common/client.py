import logging
from json import JSONDecodeError
from typing import Type, TypeVar, Optional, Self

import requests
from requests.auth import AuthBase, HTTPBasicAuth
from oic.exception import MessageException
from oic.extension.token import JWTToken
from oic.oauth2.message import SchemeError, ErrorResponse
from oic.oic import EndSessionRequest
from oic.oic.message import Message, ProviderConfigurationResponse, AuthorizationRequest, AuthorizationResponse, \
    AuthorizationErrorResponse, AccessTokenResponse, AccessTokenRequest, TokenErrorResponse, RegistrationRequest, \
    RegistrationResponse, ClientRegistrationErrorResponse
from oic.utils.keyio import KeyJar

from .errors import OidcProviderError, OidcValidationError, OidcRequestError
from .tokens import Tokens, AccessTokenClaims
from .registration import RegistrationResult

logger = logging.getLogger("ksi_oidc_common")

TMessage = TypeVar('TMessage', bound=Message)


class _BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, request):
        request.headers["authorization"] = "Bearer " + self.token
        return request


class OidcClient:
    """
    A stateless OpenID Connect client based on the `pyoidc` library.

    Create new instances using the `OidcClient.load()` method.
    """

    provider_configuration: ProviderConfigurationResponse

    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    @classmethod
    def load(cls, issuer: str, **kwargs) -> Self:
        """
        Creates a new `OidcClient` instance and fetches the OIDC Provider configuration
        from <issuer>/.well-known/openid-configuration.
        """

        client = cls(**kwargs)
        client._load(issuer)
        return client

    def __init__(
        self,
        login_requested_scopes: list[str],
        offline_requested_scopes: list[str],
        home_uri: Optional[str] = None,
        logo_uri: Optional[str] = None,
        callback_uri: Optional[str] = None,
        post_logout_redirect_uri: Optional[str] = None,
        # kwargs can be used when subclassing `OidcClient`
        **_kwargs,
    ):
        """
        This constructor should not be called directly,
        use the OidcClient.load() method instead.
        """

        self.login_requested_scopes = login_requested_scopes
        self.offline_requested_scopes = offline_requested_scopes
        self.home_uri = home_uri
        self.logo_uri = logo_uri
        self.callback_uri = callback_uri
        self.post_logout_redirect_uri = post_logout_redirect_uri

        self.keyjar = KeyJar()
        # The provider configuration will be stored in `_load()`,
        # so access to the uninitialized `provider_configuration` attribute
        # is unlikely.
        self.provider_configuration = None # type: ignore

    def set_credentials(self, client_id: str, client_secret: str):
        if self.callback_uri is None or self.post_logout_redirect_uri is None:
            raise ValueError("The callback_uri and post_logout_redirect_uri must be set before calling set_credentials")
        self.client_id = client_id
        self.client_secret = client_secret

    def _get_basic_auth(self) -> HTTPBasicAuth:
        return HTTPBasicAuth(self.client_id, self.client_secret)

    def _handle_response(
        self,
        response: requests.Response,
        success_response_type: Type[TMessage],
        error_response_type: Optional[Type[ErrorResponse]],
        ignore_scheme_error: bool = False,
    ) -> TMessage:
        if not response.ok:
            if error_response_type is not None:
                try:
                    error_message = error_response_type()
                    error_message.from_dict(response.json())
                    error_message.verify(keyjar=self.keyjar)
                    raise OidcProviderError(error_message)
                except (MessageException, JSONDecodeError) as e:
                    # These errors should lead to raising OidcRequestError
                    # Other errors are unexpected and are passed to the caller.
                    pass
            raise OidcRequestError(f"Received an invalid error response from the OIDC Provider:\n{response.text}")

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
                raise OidcRequestError(f"Received an invalid error response from the OIDC Provider: {query_params}")

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
        auth: Optional[AuthBase] = None,
    ) -> TMessage:
        response = requests.get(url, auth=auth)
        return OidcClient._handle_response(self, response, success_response_type, error_response_type, ignore_scheme_error)

    def _post_request(
        self,
        success_response_type: Type[TMessage],
        error_response_type: Optional[Type[ErrorResponse]],
        url: str,
        request_body: Message,
        auth: Optional[AuthBase] = None,
        send_json: bool = False,
        method: str = 'POST'
    ) -> TMessage:
        kwargs = {
            ('json' if send_json else 'data'): request_body.to_dict(),
        }
        response = requests.request(method, url, auth=auth, **kwargs)
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

    def _unpack_access_token(self, access_token: str) -> AccessTokenClaims:
        jwt = JWTToken(
            typ='A', # Access token
            keyjar=self.keyjar,
        )
        result = jwt.unpack(access_token)

        return AccessTokenClaims(
            # See https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc_token_role_mappings
            realm_roles = result.get("realm_access", {}).get("roles", []),
            client_roles = result.get("resource_access", {}).get(self.client_id, {}).get("roles", []),
        )

    def _parse_tokens_response(self, response: AccessTokenResponse) -> Tokens:
        access_token_claims = self._unpack_access_token(response["access_token"])
        return Tokens.from_response(response, access_token_claims)

    def get_authentication_url(self, nonce: str, state: str, prompt_none: bool) -> str:
        request_args = {
            'client_id': self.client_id,
            'response_type': "code",
            'scope': " ".join(set([*self.login_requested_scopes, "openid"])),
            'nonce': nonce,
            "redirect_uri": self.callback_uri,
            "state": state,
        }
        if prompt_none:
            request_args['prompt'] = 'none'

        return self._create_redirect_url(
            self.provider_configuration['authorization_endpoint'],
            AuthorizationRequest(**request_args),
        )

    def get_logout_url(self, id_token_hint: Optional[str]) -> str:
        request_args = {
            "id_token_hint": id_token_hint,
            "post_logout_redirect_uri": self.post_logout_redirect_uri,
        }
        return self._create_redirect_url(
            self.provider_configuration['end_session_endpoint'],
            EndSessionRequest(**request_args),
        )

    def parse_authorization_callback_response(self, query_params: dict) -> AuthorizationResponse:
        return self._handle_callback_response(query_params, AuthorizationResponse, AuthorizationErrorResponse)

    def exchange_code_for_access_token(
        self,
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
            'redirect_uri': self.callback_uri,
        }
        response = self._post_request(
            AccessTokenResponse,
            TokenErrorResponse,
            self.provider_configuration['token_endpoint'],
            AccessTokenRequest(**request_args),
            auth=self._get_basic_auth()
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
        response = self._post_request(
            AccessTokenResponse,
            TokenErrorResponse,
            self.provider_configuration['token_endpoint'],
            AccessTokenRequest(**request_args),
            auth=self._get_basic_auth()
        )
        return self._parse_tokens_response(response)


    # Methods for OpenId Connect dynamic client registration

    def _get_registration_configuration_dict(self) -> dict:
        return {
            'client_name': 'Gutenberg',
            'logo_uri': self.logo_uri,
            'application_type': 'web',
            'client_uri': self.home_uri,

            'redirect_uris': [self.callback_uri],
            'post_logout_redirect_uris': [self.post_logout_redirect_uri],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method': 'client_secret_basic',
            'scope': " ".join(set([*self.login_requested_scopes, *self.offline_requested_scopes])),
            # TODO: Add PKCE-specific config
        }

    def register(
        self,
        registration_access_token: str,
    ) -> RegistrationResult:
        """
        Register or modify the client using OpenID Connect dynamic client registration.
        The `registration_client_uri` is used for modyfing the existing client,
        if `None` is passed a new client is registered instead.
        """

        request_args = self._get_registration_configuration_dict()
        # TODO: Generate default roles if possible?
        response = self._post_request(
            RegistrationResponse,
            ClientRegistrationErrorResponse,
            self.provider_configuration['registration_endpoint'],
            request_body = RegistrationRequest(**request_args),
            auth = _BearerAuth(registration_access_token),
            send_json = True,
        )
        return RegistrationResult.from_response(response)

    def _get_registration_info_response(self, registration_access_token: str, registration_client_uri: str) -> RegistrationResponse:
        return self._get_request(
            RegistrationResponse,
            ClientRegistrationErrorResponse,
            registration_client_uri,
            auth = _BearerAuth(registration_access_token),
        )

    def get_registration_info(self, registration_access_token: str, registration_client_uri: str) -> RegistrationResult:
        response = self._get_registration_info_raw(registration_access_token, registration_client_uri)
        return RegistrationResult.from_response(response)

    def modify_registration(
        self,
        registration_access_token: str,
        registration_client_uri: str,
        expected_client_id: str,
    ) -> RegistrationResult:
        registration_info_response = self._get_registration_info_response(registration_access_token, registration_client_uri)
        if registration_info_response["client_id"] != expected_client_id:
            raise OidcValidationError(
                f"The client ID returned by the OIDC Provider in a dynamic registration request:\n"
                f"{registration_info_response['client_id']}\n"
                f"does not match the one configured:\n"
                f"${expected_client_id}",
            )
        modify_request = registration_info_response.copy()
        modify_request.from_dict(self._get_registration_configuration_dict())
        modify_request.pop('registration_access_token', None)
        modify_request.pop('registration_client_uri', None)
        modify_request.pop('client_secret_expires_at', None)
        modify_request.pop('client_id_issued_at', None)
        response = self._post_request(
            RegistrationResponse,
            ClientRegistrationErrorResponse,
            registration_client_uri,
            request_body = modify_request,
            auth = _BearerAuth(registration_access_token),
            send_json = True,
            method = 'PUT',
        )
        return RegistrationResult.from_response(response)
