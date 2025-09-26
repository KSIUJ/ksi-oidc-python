import logging
from typing import Optional, Callable, Awaitable, Dict, List
from fastapi import Request, Response, status
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from ksi_oidc_common.tokens import AccessTokenClaims
from ksi_oidc_common.client import OidcClient

from .models import Role
from .session_manager import session_manager, SessionData

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
        protected_paths: Optional[list[str]] = None,
        public_paths: Optional[list[str]] = None,
        login_redirect_path: str = "/auth/login",
        oidc_client : OidcClient = None
    ):
        super().__init__(app)
        self.session_cookie_name = session_cookie_name
        self.session_cookie_httponly = session_cookie_httponly
        self.session_cookie_secure = session_cookie_secure
        self.session_cookie_samesite = session_cookie_samesite
        self.route_configuration = route_configuration
        self.role_hierarchy = role_hierarchy
        self.protected_paths = protected_paths or []
        self.public_paths = public_paths or [
            "/auth/login", 
            "/auth/callback", 
            "/auth/logout",
            "/docs",
            "/openapi.json",
            "/health"
        ]
        self.login_redirect_path = login_redirect_path
        self.oidc_client = oidc_client

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
        request.state.user_id = session_data.user_id if session_data else None
        request.state.tokens = session_data.tokens if session_data else None
        
 
        if self._requires_auth(request.url.path):
            if not request.state.is_authenticated:
                logger.info(f"Redirecting unauthenticated user from {request.url.path}")
                return RedirectResponse(
                    url=self.login_redirect_path,
                    status_code=302
                )
            if not self.is_path_allowed(request.url.path, self.oidc_client._unpack_access_token(session_data.user_id)):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content="Insufficient role permissions"
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
        user_roles = user_role_tokens.realm_roles
        user_level : int = 1
        for user_role in user_roles:
            if user_role in self.role_hierarchy:
                user_level = self.role_hierarchy.index(user_role) if self.role_hierarchy.index(user_role) > 1 else 1
        
        normalized_path = self._normalize_path(path)
        
        # Check if the path starts with any route from higher roles
        for i in range(user_level + 1, len(self.role_hierarchy)):
            higher_role = self.role_hierarchy[i]
            print(higher_role)
            for route in self.route_configuration.get(higher_role, []):
                normalized_route = self._normalize_path(route)
                print(normalized_route)
                if normalized_path.startswith(normalized_route):
                    return False
        
        return True
    
    def _requires_auth(self, path: str) -> bool:
        """Check if a path requires authentication"""

        # if self.route_configuration:
        #     return any(path.startswith(protected) for protected in self.protected_paths)
        

        return not any(path.startswith(public) for public in self.route_configuration[Role.PUBLIC])
    
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



def get_or_create_session(request: Request) -> str:
    """Get existing session key or create a new one"""
    session_key = request.state.session_key
    
    if not session_key:
        session_key = session_manager.create_session()
        request.state.new_session_key = session_key  
        request.state.session_key = session_key
        

        session_data = session_manager.get_session(session_key)
        request.state.session_data = session_data
        request.state.is_authenticated = False
        request.state.user_id = None
        request.state.tokens = None
        
    return session_key


def require_auth(request: Request) -> SessionData:
    """
    Helper function to require authentication in route handlers.
    Raises HTTPException if user is not authenticated.
    """
    from fastapi import HTTPException, status
    
    if not request.state.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    return request.state.session_data


def logout_session(request: Request) -> bool:
    """Helper function to logout current session"""
    session_key = request.state.session_key
    if session_key:
        success = session_manager.logout_user(session_key)
        if success:
            request.state.is_authenticated = False
            request.state.user_id = None
            request.state.tokens = None
        return success
    return False


def delete_session_cookie(response: Response, cookie_name: str = "session_id"):
    """Helper function to delete session cookie"""
    response.delete_cookie(key=cookie_name)