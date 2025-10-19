from fastapi import FastAPI, Request

app = FastAPI()

from typing import Dict, List
from .models import Role
from .auth_middleware import AuthMiddleware
from .auth_router import router as auth_router
from .example_router import router as example_router

# Route configuration: Role -> List of routes
"""
    Needs to include full routes but every route under the route included will require the highest level role from the defined hierarchy the route included in
    
    1)
    Role.USER: ["/example"],
    Role.MANAGER: ["/example"]
    Role.ADMIN: ["/example"],

    Will require Role.ADMIN to access /example and all subroutes of it (/example/1, /example/2, etc..)
    
    2)
    Role.USER: ["/example/1"],
    Role.ADMIN: ["/example"],

    Also will require Role.ADMIN to access /example and all subroutes of it (/example/1, /example/2/1, etc..), so Role.User will not be able to access /example/1
    
    3)
    
    Role.USER: ["/example"],
    Role.ADMIN: ["/example/1"],
    
    Role.USER will be able to access any route /example/{route}/ where route != 1 and all the /example/1/... will also be not accessible by Role.USER

"""
Role.add_role("MANAGER", "manager")
Role.get_all_roles()

ROLE_ROUTES: Dict[Role, List[str]] = {
    Role.PUBLIC: ["/"],
    Role.USER: ["/example/protected", "/docs", "/openapi.json"],
    Role.MANAGER: ["/example/manager"],
    Role.ADMIN: ["/example/admin"],
}

app.add_middleware(
    AuthMiddleware,
    user_repository_instance = None,
    session_cookie_name="session_id",
    session_cookie_secure=True, 
    route_configuration = ROLE_ROUTES,
    login_redirect_path="/auth/login",
    role_hierarchy = [Role.PUBLIC, Role.USER, Role.MANAGER, Role.ADMIN]
)

app.include_router(auth_router, prefix="/auth")

app.include_router(example_router, prefix="/example")

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
