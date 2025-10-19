# ksi-oidc-fastapi

OpenID Connect (OIDC) authentication integration for FastAPI applications.
This package provides a middleware, router and session manager to add OIDC(keycloak) login, callback and logout flows, and protected routes based on roles.

## What this package provides

- `AuthMiddleware` — middleware that:
  - Loads session from cookie and sets session data on `request.state`
  - Refreshes access tokens when needed
  - Allows route-level authentication and role-based access using a configurable route map
- `auth_router` — prebuilt router with endpoints:
  - `GET /auth/login` — start OIDC login
  - `GET /auth/callback` — OIDC callback handler
  - `GET /auth/logout` — logout and redirect to IdP
  - `GET /auth/protected` — example protected route
  - `GET /auth/admin` — example admin route
- `session_manager` — in-memory session store
- `get_oidc_client()` — helper that reads OIDC config from `OidcConfiguration`

## Configuration

### 1. Environment variables (.env)

Provide OIDC provider and client credentials in a `.env` file at repository root (the package uses pydantic settings).

Required variables:
- `ISSUER` (e.g. https://your-keycloak.example/realms/your-realm)
- `CLIENT_ID`
- `CLIENT_SECRET`
- `callback_uri` (should contain your app hostname, e.g. http://someappname.com/)
- `post_logout_redirect_uri`
- `home_uri`

Example `.env`:

```env
ISSUER=http://localhost:8080/realms/myrealm
CLIENT_ID=TestClientSecret
CLIENT_SECRET=g8rTPq20CQEWV3xODDX4jHYZe5qa1BY8
callback_uri="http://localhost:8081/auth/callback"
post_logout_redirect_uri="http://localhost:8081"
home_uri="http://localhost:8081"
```

For Docker Compose, add to your service configuration:

```yaml
environment:
  ISSUER: http://localhost:8080/realms/myrealm
  CLIENT_ID: TestClientSecret
  CLIENT_SECRET: g8rTPq20CQEWV3xODDX4jHYZe5qa1BY8
  callback_uri: "http://localhost:8081/auth/callback"
  post_logout_redirect_uri: "http://localhost:8081"
  home_uri: "http://localhost:8081"
```

### 2. OIDC settings

The package exposes `OidcConfiguration` (in `models.py`) with fields:
- issuer, client_id, client_secret, callback_uri, home_uri, post_logout_redirect_uri, login_requested_scopes

Edit values or set env vars to configure callback and redirect URIs.

### 3. Role configuration

- Add or edit roles using `from ksi_oidc_fastapi.models import Role` methods
- Configure which routes require which role using a mapping `Role -> List[str]`
- Define role hierarchy to determine which roles are considered higher/lower

## Integration example

```python
from fastapi import FastAPI, Request
from ksi_oidc_fastapi.auth_middleware import AuthMiddleware
from ksi_oidc_fastapi.auth_router import router as auth_router
from ksi_oidc_fastapi.example_router import router as example_router
from ksi_oidc_fastapi.models import Role
from typing import Dict, List

app = FastAPI()

# Add custom roles
Role.add_role("MANAGER", "manager")

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
ROLE_ROUTES: Dict[Role, List[str]] = {
    Role.PUBLIC: ["/"],  # All routes are accessible to public users by default
    Role.USER: ["/example/protected", "/docs", "/openapi.json"],
    Role.MANAGER: ["/example/manager"],
    Role.ADMIN: ["/example/admin"],
}

# Implement and pass your user repository instance. It should support at minimum:
# - get_user_by_sub(sub: str) -> Optional[user_obj]
# - create_user(...) (optional)
# - should be async def
user_repo = None

app.add_middleware(
    AuthMiddleware,
    user_repository_instance=user_repo,
    session_cookie_name="session_id",
    session_cookie_secure=True,
    route_configuration=ROLE_ROUTES,
    login_redirect_path="/auth/login",
    role_hierarchy=[Role.PUBLIC, Role.USER, Role.MANAGER, Role.ADMIN],
)

app.include_router(auth_router, prefix="/auth")  # If you change the prefix, update it in .env or docker-compose

app.include_router(example_router, prefix="/example") # Example router in which you will be able to test /protected if user is authenticated and /admin if user has admin role on keycloak

@app.get("/")
async def root(request: Request):
    if getattr(request.state, "is_authenticated", False):
        return {"message": "Hello authenticated user", "user": getattr(request.state, "user", None)}
    return {"message": "Hello anonymous user"}
```

### Notes

- The middleware sets `request.state.session_key`, `request.state.session_data`, `request.state.tokens`, `request.state.is_authenticated`, `request.state.role`, and `request.state.user`
- The `user_repository_instance` is optional but recommended: when present, the middleware will try to load or create a local user record from the OIDC `sub` claim and store it in `request.state.user`

## Token refresh behavior

- Access tokens are checked on each request; if they are near expiry the middleware will attempt to refresh them using the refresh token stored in the session
- If refresh fails (e.g. refresh token expired) the user is logged out and the session cleared

## Run the example app

Start the FastAPI app with Uvicorn:

```bash
uvicorn your_module:app --port 8081
```
or
```bash
uv run uvicorn your_module:app --port 8081
```

Replace `your_module:app` with the import path for the module that defines `app` in your project.

If you don't have a keycloak server setup one how you want from here https://www.keycloak.org
if you want to get it in docker fast setup use `docker run --name keycloak -p 8080 quay.io/keycloak/keycloak start-dev`

# Running/Testing Notes
- There is networking issue if you want to run both your app and keycloak in docker because docker isolates it's containers networks and even if you add app and keycloak to a docker network it will have to access the keycloak by {container_name}:port and it is only container specific that results in an impossible redirect. IT IS NOT A PROBLEM IF YOU LAUNCH YOUR APP LOCALLY!!
It might be just some configuration issues, I wasn't able to find it. 

## Troubleshooting

- If the middleware complains about configuration, verify `.env` values
- If callback or redirect behaviour is incorrect, check client settings in your OIDC provider and ensure `callback_uri` matches exactly
