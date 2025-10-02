import secrets
from fastapi import FastAPI, Request, HTTPException, Response,APIRouter
from fastapi.responses import RedirectResponse, JSONResponse

from ksi_oidc_common.client import OidcClient 
from ksi_oidc_common.errors import OidcProviderError, OidcError
from .session_manager import session_manager
from .auth_middleware import AuthMiddleware, get_or_create_session, logout_session, delete_session_cookie
from .oidc_client import get_oidc_client

import logging

router = APIRouter(tags=["auth"])

@router.get("/login")
async def login(request: Request):
    """Initiate OIDC login flow"""
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

@router.get("/callback")
async def auth_callback(request: Request):
    """Handle OIDC callback"""
    session_key = get_or_create_session(request)
    query_params = dict(request.query_params)
    # logging.error(f"Query params: {query_params}")

    if not session_manager.verify_oauth_state(session_key, query_params.get("state")):
        logging.error("Invalid state parameter")
        return RedirectResponse(
            url=f"{router.prefix}/login",
            status_code=302
        )

    session_data = session_manager.get_session(session_key)
    if not session_data or not session_data.nonce:
        logging.error("Invalid session state: Missing session data or nonce")
        return JSONResponse(
            content={
                "error": "invalid_session",
                "error_description": "Invalid session state. Please ensure cookies are enabled."
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
        
        return JSONResponse(
            content={
                "error": "oidc_provider_error",
                "error_description": error.response.get("error_description") or "Authentication failed",
                "provider_error": error.response.get("error")
            },
            status_code=400
        )

    except OidcError as error:
        logging.error(f"Got OIDC error in callback: {str(error)}", exc_info=True)
        return JSONResponse(
            content={
                "error": "oidc_error",
                "error_description": "An unexpected error occurred during authentication"
            },
            status_code=500
        )

@router.get("/logout")
async def logout(request: Request):
    """Logout user"""
    session_data = request.state.session_data
    id_token_hint = None
    
    if session_data and session_data.tokens:
        id_token_hint = session_data.tokens.id_token
    
    if not logout_session(request):
        return RedirectResponse(url="/", status_code=302)
        
    
    logout_url = get_oidc_client().get_logout_url(id_token_hint)
    
    response = RedirectResponse(url=logout_url, status_code=302)
    delete_session_cookie(response)
    
    return response


@router.get("/protected")
async def protected_route(request: Request):
    """Example protected route"""
    session_key = get_or_create_session(request) 
    session_data = session_manager.get_session(session_key)
    
    user_claims = {}
    if session_data.tokens and session_data.tokens.id_token_claims:
        id_token_claims = session_data.tokens.id_token_claims
        user_claims = {
            "email": id_token_claims.get("email"),
            "roles": id_token_claims.get("realm_access", {}).get("roles"),
            "realm_access": id_token_claims.get("realm_access", {}),
            "preferred_username": id_token_claims.get("preferred_username"),
            "profile": id_token_claims.get("profile"),
            "basic": id_token_claims
        }
    
    return {
        "message": "You are authenticated!",
        "user_claims": user_claims,
        "session_info": {
            "created_at": session_data.created_at,
            "last_accessed": session_data.last_accessed
        }
    }
@router.get("/admin")
async def admin_route(request: Request):
    """Example admin route"""
    session_data = getattr(request.state,"session_data", None)
    
    user_claims = {}
    if session_data and session_data.tokens and session_data.tokens.id_token_claims:
        id_token_claims = session_data.tokens.id_token_claims
        user_claims = {
            "email": id_token_claims.get("email"),
            "roles": id_token_claims.get("realm_access", {}).get("roles"),
            "realm_access": id_token_claims.get("realm_access", {}),
            "preferred_username": id_token_claims.get("preferred_username"),
            "profile": id_token_claims.get("profile"),
            "basic": id_token_claims
        }
    
    return {
        "message": "You are authenticated!",
        "user_claims": user_claims,
        "session_info": {
            "created_at": session_data.created_at,
            "last_accessed": session_data.last_accessed
        }
    }