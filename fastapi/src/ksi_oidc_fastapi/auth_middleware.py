import logging
from typing import Optional, Callable, Awaitable, Dict, List
from fastapi import Request, Response, status
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from datetime import UTC, datetime, timedelta

from ksi_oidc_common.tokens import AccessTokenClaims, Tokens
from ksi_oidc_common.errors import OidcProviderError

from .oidc_client import get_oidc_client

from .models import Role
from .session_manager import session_manager

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for handling OIDC authentication sessions.
    
    This middleware:
    1. Extracts session key from cookies
    2. Loads session data and stores it in request.state.session_key
    3. Provides helper properties for checking authentication
    """
    
    def __init__(
        self, 
        app,
        user_repository_instance : object,
        session_cookie_name: str = "session_id",
        session_cookie_httponly: bool = True,
        session_cookie_secure: bool = True,  
        session_cookie_samesite: str = "lax",
        route_configuration : Dict[Role, List[str]] = {
                                                        Role.PUBLIC: ["/auth/login", "/auth/callback", "/auth/logout", "/docs", "/openapi.json"],
                                                        Role.USER: ["/protected"],
                                                        Role.ADMIN: ["/admin"],
                                                    },
        role_hierarchy : List[Role] = [Role.PUBLIC, Role.USER, Role.ADMIN],
        login_redirect_path: str = "/auth/login",
    ):
        super().__init__(app)
        self.user_repository_instance = user_repository_instance
        self.session_cookie_name = session_cookie_name
        self.session_cookie_httponly = session_cookie_httponly
        self.session_cookie_secure = session_cookie_secure
        self.session_cookie_samesite = session_cookie_samesite
        self.route_configuration = route_configuration
        self.role_hierarchy = role_hierarchy
        self.login_redirect_path = login_redirect_path

    async def dispatch(
        self, 
        request: Request, 
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:

        session_key = request.cookies.get(self.session_cookie_name)
        

        request.state.session_key = session_key
        

        session_data = session_manager.get_session(session_key) if session_key else None
        request.state.session_data = session_data
        

        request.state.is_authenticated = (
            session_data is not None and session_data.is_authenticated()
        )
        request.state.tokens = session_data.tokens if session_data else None
        logger.error(f"Tokens Have Been Renewed")
        refresh_oidc_auth_session(request)
        if getattr(self.user_repository_instance, "get_user_by_sub", None) and getattr(self.user_repository_instance, "create_user", None):
            sub = getattr(session_data.tokens, "sub", None)
            if sub:
                setattr(request.state, "user", self.user_repository_instance.get_user_by_sub(sub))
                if not getattr(request.state, "user", None):
                    setattr(request.state, "user", self.user_repository_instance.get_user_by_sub(sub))
            else:
                logger.error("Token parsing resulted in identificator sub == None")
                
        else:
            logger.error("get_user_by_sub or create_user is not defined in the passed to the middleware user_repository instance")
        
        if self._requires_auth(request.url.path):
            if not request.state.is_authenticated:
                logger.error(f"Redirecting unauthenticated user from {request.url.path}")
                return RedirectResponse(
                    url=self.login_redirect_path,
                    status_code=status.HTTP_302_FOUND
                )
            if not self.is_path_allowed(request.url.path, get_oidc_client()._unpack_access_token(session_data.tokens.access_token)):
                return RedirectResponse(
                    url="/",
                    status_code=status.HTTP_302_FOUND,
                )

        response = await call_next(request)
        

        new_session_key = getattr(request.state, 'new_session_key', None)
        if new_session_key:
            self._set_session_cookie(response, new_session_key)
        
        return response
    
    def _normalize_path(self, path: str) -> str:
        """Remove trailing slash except for root path."""
        if path == "/" or not path:
            return "/"
        return path.rstrip("/")
    
    def is_path_allowed(self, path: str, user_role_tokens : AccessTokenClaims) -> bool:
        """Check if user role can access the path."""
        user_roles = user_role_tokens.client_roles
        user_level : int = 1
        for user_role in user_roles:
            if user_role in self.role_hierarchy:
                user_level = self.role_hierarchy.index(user_role) if self.role_hierarchy.index(user_role) > 1 else 1
        
        normalized_path = self._normalize_path(path)
        
        for i in range(user_level + 1, len(self.role_hierarchy)):
            higher_role = self.role_hierarchy[i]
            for route in self.route_configuration.get(higher_role, []):
                normalized_route = self._normalize_path(route)
                if normalized_path.startswith(normalized_route):
                    return False
        
        return True
    
    def _requires_auth(self, path: str) -> bool:
        """Check if a path requires authentication"""
        return not any(path == public for public in self.route_configuration[Role.PUBLIC])
    
    def _set_session_cookie(self, response: Response, session_key: str):
        """Set session cookie on response"""
        response.set_cookie(
            key=self.session_cookie_name,
            value=session_key,
            httponly=self.session_cookie_httponly,
            secure=self.session_cookie_secure,
            samesite=self.session_cookie_samesite,
            max_age=session_manager.session_timeout
        )

    def get_user_data(self, request, oidc_id_token_claims=None, oidc_access_token_claims=None):
        if oidc_id_token_claims is None or oidc_access_token_claims is None:
            return None

        user = self._find_existing_user(oidc_id_token_claims)
        if user is None:
            user = self._create_user(oidc_id_token_claims)

        self._update_user(user, oidc_id_token_claims, oidc_access_token_claims)
        return user
    
    
def refresh_access_token(request: Request, refresh_token: str):
    oidc_client = get_oidc_client()
    tokens = oidc_client.refresh_access_token(refresh_token)
    session_key = get_or_create_session(request)
    session_manager.update_session_tokens(session_key, tokens)

def refresh_oidc_auth_session(request: Request):
    """
    Verify the validity of the access token and refresh it if it has expired.
    Logs the user out if refreshing the access token fails.

    `OidcAuthMiddleware` calls this function for all requests.
    """

    if not request.state.is_authenticated:
        return

    try:
        session_tokens : Tokens = request.state.session_data.tokens
    except KeyError:
        logger.error(
            "Failed to access sessionData. Signing the user out."
        )
        logout_session(request)
        return

    if datetime.fromisoformat(str(session_tokens.access_expires_at)) > datetime.now(
        UTC
    ) + timedelta(seconds=5):
        # The access token is still valid and will be valid for at least 5 more seconds
        return

    logger.debug(
        "The access token has expired, refreshing"
    )
    try:
        refresh_access_token(request, session_tokens.refresh_token)
        logger.info("Refreshed expired access token")
        logger.info(f"Redirecting user to update info with new tokens to {request.url.path}")
        return RedirectResponse(
            url=request.url.path,
            status_code=status.HTTP_302_FOUND
        )
    except Exception as error:
        if (
            isinstance(error, OidcProviderError)
            and error.response["error"] == "invalid_grant"
        ):
            logger.info("Refresh token has expired, signing them out")
            logout_session(request)
            return
        
        logger.error(
            "Failed to refresh access token, signing them out",
            exc_info=True,
        )
        logout_session(request)
        raise

def get_or_create_session(request: Request) -> str:
    """Get existing session key or create a new one"""
    session_key = request.state.session_key
    
    
    if not session_key or not session_manager.get_session(session_key):
        session_key = session_manager.create_session()
        request.state.new_session_key = session_key  
        request.state.session_key = session_key
        

        session_data = session_manager.get_session(session_key)
        request.state.session_data = session_data
        request.state.is_authenticated = False
        request.state.tokens = None
        
    return session_key


def logout_session(request: Request) -> bool:
    """Helper function to logout current session"""
    session_key = request.state.session_key
    if session_key:
        success = session_manager.logout_user(session_key)
        if success:
            request.state.is_authenticated = False
            request.state.tokens = None
        return success
    return False


def delete_session_cookie(response: Response, cookie_name: str = "session_id"):
    """Helper function to delete session cookie"""
    response.delete_cookie(key=cookie_name)