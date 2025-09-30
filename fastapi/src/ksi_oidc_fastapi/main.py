from fastapi import FastAPI, Request

app = FastAPI()


from typing import Dict, List
from .models import Role
from .auth_middleware import AuthMiddleware
from .auth_router import router as auth_router
# Route configuration: Role -> List of routes
# Needs to include full routes but every route under the route included will also require the highest level the route included in
ROLE_ROUTES: Dict[Role, List[str]] = {
    Role.PUBLIC: ["/", "/auth/login", "/auth/callback", "/auth/logout"],
    Role.USER: ["/auth/protected", "/docs", "/openapi.json"],
    Role.ADMIN: ["/auth/admin"],
}

app.add_middleware(
    AuthMiddleware,
    user_repository_instance = None,
    session_cookie_name="session_id",
    session_cookie_httponly=True,
    session_cookie_secure=True, 
    route_configuration = ROLE_ROUTES,
    login_redirect_path="/auth/login",
    role_hierarchy = [Role.PUBLIC, Role.USER, Role.ADMIN]
)

app.include_router(auth_router)

@app.get("/")
async def root(request: Request):
    """Public route"""
    if getattr(request.state, "is_authenticated", None):
        return {"message": f"Hello authenticated {getattr(request.state, "user", None)}"}
    else:
        return {"message": "Hello anonymous user!", "authenticated": False}



@app.on_event("startup")
async def startup_event():
    pass