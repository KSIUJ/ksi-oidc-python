import logging
from pathlib import Path
from requests.exceptions import ConnectionError
import secrets

from fastapi import Request, APIRouter
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from ksi_oidc_common.errors import OidcProviderError, OidcError

from .session_manager import session_manager
from .auth_middleware import get_or_create_session, logout_session, delete_session_cookie
from .oidc_client import get_oidc_client

router = APIRouter(tags=["auth"])

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

@router.get("/login")
async def login(request: Request):
    """Initiate OIDC login flow"""
    try:
        session_key = get_or_create_session(request)
       
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
       
        session_manager.set_oauth_state(session_key, state, nonce)
       
        auth_url = get_oidc_client().get_authentication_url(
            nonce=nonce,
            state=state,
            prompt_none=False
        )
       
        return RedirectResponse(url=auth_url, status_code=302)
    
    except ConnectionError as error:
        logging.error(f"Failed to connect to OIDC provider: {str(error)}")
        return templates.TemplateResponse(
            "callback_error.html",
            {
                "request": request,
                "error": "connection_error",
                "error_description": "Unable to connect to the authentication provider. Please try again later or contact support.",
                "retry_url": f"{router.prefix}/login"
            },
            status_code=503
        )
    
    except Exception as error:
        logging.error(f"Unexpected error during login: {str(error)}", exc_info=True)
        return templates.TemplateResponse(
            "callback_error.html",
            {
                "request": request,
                "error": "unexpected_error",
                "error_description": "An unexpected error occurred while initiating authentication. Please try again.",
                "retry_url": f"{router.prefix}/login"
            },
            status_code=500
        )

@router.get("/callback")
async def auth_callback(request: Request):
    """Handle OIDC callback"""
    session_key = get_or_create_session(request)
    query_params = dict(request.query_params)
    
    if not session_manager.verify_oauth_state(session_key, query_params.get("state")):
        logging.error("Invalid state parameter")
        return templates.TemplateResponse(
            "callback_error.html",
            {
                "request": request,
                "error": "invalid_state",
                "error_description": "Invalid state parameter. This may be due to a session timeout or CSRF attack attempt.",
                "retry_url": f"{router.prefix}/login"
            },
            status_code=400
        )
    
    session_data = session_manager.get_session(session_key)
    if not session_data or not session_data.nonce:
        logging.error("Invalid session state: Missing session data or nonce")
        return templates.TemplateResponse(
            "callback_error.html",
            {
                "request": request,
                "error": "invalid_session",
                "error_description": "Invalid session state. Please ensure cookies are enabled in your browser.",
                "retry_url": f"{router.prefix}/login"
            },
            status_code=400
        )
    
    try:
        auth_response = get_oidc_client().parse_authorization_callback_response(query_params)
        tokens = get_oidc_client().exchange_code_for_access_token(
            code=auth_response["code"],
            expected_nonce=session_data.nonce
        )
        session_manager.set_user_authenticated(session_key, tokens)
        return RedirectResponse(url="/", status_code=302)
    
    except OidcProviderError as error:
        logging.error(
            f"Received OIDC provider error: {error.response.get('error')}, "
            f"Description: {error.response.get('error_description')}"
        )
        return templates.TemplateResponse(
            "callback_error.html",
            {
                "request": request,
                "error": "oidc_provider_error",
                "error_description": error.response.get("error_description") or "Authentication failed",
                "provider_error": error.response.get("error"),
                "retry_url": f"{router.prefix}/login"
            },
            status_code=400
        )
    
    except OidcError as error:
        logging.error(f"Got OIDC error in callback: {str(error)}", exc_info=True)
        return templates.TemplateResponse(
            "callback_error.html",
            {
                "request": request,
                "error": "oidc_error",
                "error_description": "An unexpected error occurred during authentication. Please try again.",
                "retry_url": f"{router.prefix}/login"
            },
            status_code=500
        )

@router.get("/logout")
async def logout(request: Request):
    """Logout user"""
    try:
        session_data = request.state.session_data
        id_token_hint = None
       
        if session_data and session_data.tokens:
            id_token_hint = session_data.tokens.id_token
       
        logout_success = logout_session(request)
        
        if not logout_success:
            return RedirectResponse(url="/", status_code=302)
       
        logout_url = get_oidc_client().get_logout_url(id_token_hint)
       
        response = RedirectResponse(url=logout_url, status_code=302)
        delete_session_cookie(response)
       
        return response
    
    except ConnectionError as error:
        logging.error(f"Failed to connect to OIDC provider during logout: {str(error)}")
        response = RedirectResponse(url="/", status_code=302)
        delete_session_cookie(response)
        return response
    
    except Exception as error:
        logging.error(f"Unexpected error during logout: {str(error)}", exc_info=True)
        response = RedirectResponse(url="/", status_code=302)
        delete_session_cookie(response)
        return response
