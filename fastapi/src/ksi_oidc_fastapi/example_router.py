from fastapi import Request, APIRouter
from .session_manager import session_manager
from .auth_middleware import get_or_create_session

router = APIRouter(tags=["example"])

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
