import secrets
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import RedirectResponse, JSONResponse

from ksi_oidc_common.client import OidcClient 
from ksi_oidc_common.errors import OidcProviderError, OidcError
from .session_manager import session_manager
from .auth_middleware import AuthMiddleware, get_or_create_session, require_auth, logout_session, delete_session_cookie

app = FastAPI()


from typing import Dict, List
from .models import Role
# Route configuration: Role -> List of routes
# Needs to include full routes but every route under the route included will also require the highest level the route included in
ROLE_ROUTES: Dict[Role, List[str]] = {
    Role.PUBLIC: ["/auth/login", "/auth/callback", "/auth/logout", "/docs", "/openapi.json"],
    Role.USER: ["/protected"],
    Role.ADMIN: ["/admin"],
}

oidc_client = OidcClient.load(
    "http://localhost:8080/realms/Mordor-2.0",
    callback_uri="http://localhost:8081/auth/callback",
    post_logout_redirect_uri="http://localhost:8081",
    home_uri="http://localhost:8081",
    login_requested_scopes=["profile","email", "roles", "phone","basic"]
)
oidc_client.set_credentials(
    "TestClientSecret",
    "g8rTPq20CQEWV3xODDX4jHYZe5qa1BY8"
)

app.add_middleware(
    AuthMiddleware,
    session_cookie_name="session_id",
    session_cookie_httponly=True,
    session_cookie_secure=True, 
    route_configuration = ROLE_ROUTES,
    protected_paths=["/protected"],  # TODO Rework path logic using Roles which are pulled from KeyCloak
    public_paths=["/auth/login", "/auth/callback", "/auth/logout", "/docs", "/openapi.json"],
    login_redirect_path="/auth/login",
    oidc_client = oidc_client
)




@app.get("/auth/login")
async def login(request: Request):
    """Initiate OIDC login flow"""
    session_key = get_or_create_session(request)
    

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    

    session_manager.set_oauth_state(session_key, state, nonce)
    

    auth_url = oidc_client.get_authentication_url(
        nonce=nonce,
        state=state,
        prompt_none=False
    )
    
    return RedirectResponse(url=auth_url, status_code=302)

import logging
@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Handle OIDC callback"""
    session_key = get_or_create_session(request)
    query_params = dict(request.query_params)
    logging.error(f"Query params: {query_params}")

    if not session_manager.verify_oauth_state(session_key, query_params.get("state")):
        logging.error("Invalid state parameter")
        return JSONResponse(
            content={
                "error": "invalid_state",
                "error_description": "Invalid state parameter"
            },
            status_code=400
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
        auth_response = oidc_client.parse_authorization_callback_response(query_params)
        logging.error(f"Auth response: {auth_response.to_dict()}")

        tokens = oidc_client.exchange_code_for_access_token(
            code=auth_response["code"],
            expected_nonce=session_data.nonce
        )
        logging.error(f"Tokens: {tokens}")
        logging.error(f"ID Token claims: {tokens.id_token}")

        user_id = tokens.id_token
        session_manager.set_user_authenticated(session_key, user_id, tokens)

        next_url = "/protected"  
        return RedirectResponse(url=next_url, status_code=302)

    except OidcProviderError as error:
        logging.error(
            f"Received OIDC provider error: {error.response.get('error')}, "
            f"Description: {error.response.get('error_description')}"
        )
        # if session_data.prompt_none and error.response.get("error") in ("login_required", "interaction_required"):
        #     logging.debug(
        #         f"Received error {error.response.get('error')} with prompt=none, redirecting to next URL"
        #     )
        #     return RedirectResponse(url="/protected", status_code=302)
        
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

@app.get("/auth/logout")
async def logout(request: Request):
    """Logout user"""
    session_data = request.state.session_data
    id_token_hint = None
    
    if session_data and session_data.tokens:
        id_token_hint = session_data.tokens.id_token
    
    logout_session(request)
    
    logout_url = oidc_client.get_logout_url(id_token_hint)
    
    response = RedirectResponse(url=logout_url, status_code=302)
    delete_session_cookie(response)
    
    return response


@app.get("/protected")
async def protected_route(request: Request):
    """Example protected route"""
    session_data = require_auth(request)  
    
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
        "user_id": request.state.user_id,
        "user_claims": user_claims,
        "session_info": {
            "created_at": session_data.created_at,
            "last_accessed": session_data.last_accessed
        }
    }
@app.get("/admin")
async def admin_route(request: Request):
    """Example admin route"""
    session_data = request.state.session_data  
    
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
        "user_id": request.state.user_id,
        "user_claims": user_claims,
        "session_info": {
            "created_at": session_data.created_at,
            "last_accessed": session_data.last_accessed
        }
    }
@app.get("/")
async def root(request: Request):
    """Public route"""
    if request.state.is_authenticated:
        return {"message": f"Hello {request.state.user_id}!", "authenticated": True}
    else:
        return {"message": "Hello anonymous user!", "authenticated": False}

@app.get("/session-info")
async def session_info(request: Request):
    """Debug endpoint to check session state"""
    return {
        "session_key": request.state.session_key,
        "is_authenticated": request.state.is_authenticated,
        "user_id": request.state.user_id,
        "session_count": session_manager.get_session_count()
    }

import asyncio

async def cleanup_sessions():
    """Periodic cleanup of expired sessions"""
    while True:
        await asyncio.sleep(3600) 
        cleaned = session_manager.cleanup_expired_sessions()
        if cleaned > 0:
            print(f"Cleaned up {cleaned} expired sessions")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_sessions())