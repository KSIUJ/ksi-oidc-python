# ksi-oidc-fastapi

OpenID Connect (OIDC) authentication integration for FastAPI applications.
This package provides a middleware, router and session manager to add OIDC(keycloak) login, callback and logout flows, and  protected routes based on roles.

## Quick overview

- Provides middleware `AuthMiddleware` that:
  - Loads session from cookie
  - Refreshes access tokens when needed
  - Sets session and auth state on `request.state`
  - Allows route-level auth and role-based access
- Provides `auth_router` with endpoints:
  - `GET /auth/login` — start OIDC login
  - `GET /auth/callback` — OIDC callback handler
  - `GET /auth/logout` — logout and redirect to IdP
  - `GET /auth/protected` — example protected route
  - `GET /auth/admin` — example admin route
- In-memory `session_manager` for session lifecycle and token storage
- `get_oidc_client()` helper reads OIDC config (from `OidcConfiguration`)

## Configuration

1. Environment (.env)

   - Provide OIDC provider and client credentials in a `.env` file at repository root (the package uses pydantic settings).
   - Required variables:
     - ISSUER (e.g. https://your-keycloak.example/realms/your-realm)
     - CLIENT_ID
     - CLIENT_SECRET

   Example `.env`:

   ```
   ISSUER=http://localhost:8080/realms/myrealm
   CLIENT_ID=TestClientSecret
   CLIENT_SECRET=g8rTPq20CQEWV3xODDX4jHYZe5qa1BY8
   ```

2. OIDC settings

   - The package exposes `OidcConfiguration` (in `models.py`) with fields:
     - issuer, client_id, client_secret, callback_uri, home_uri, post_logout_redirect_uri, login_requested_scopes
   - Edit values or set env vars to configure callback and redirect URIs.

3. Role configuration
   - Define roles Role.{RoleName} = "{RoleName on keycloak}" (in `models.py`)
   - Configure which routes require which role using a mapping Role -> List[str].
   - Define role hierarchy to determine which roles are considered higher/lower.
   

## Integration (example)

This project contains an example integration in `main.py`. Minimal example to add middleware and router to your FastAPI app:

# ksi-oidc-fastapi

OpenID Connect (OIDC) integration for FastAPI applications. This package provides a small, focused middleware, an auth router, and an in-memory session manager to add OIDC login, callback and logout flows and protect routes by role.

## What this package provides

- `AuthMiddleware` — middleware that:
  - loads session from a cookie and sets session data on `request.state`;
  - refreshes access tokens when needed;
  - allows route-level authentication and role-based access using a configurable route map;
- `auth_router` — prebuilt router with endpoints: `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/protected`, `/auth/admin` (examples);
- `session_manager` — in-memory session store (replaceable for production);
- `get_oidc_client()` — helper that reads `OidcConfiguration` (from `models.py`) for provider/client settings.

## Quick start

1. Create a FastAPI app (see `main.py` in this package for an example).
2. Add the middleware and include the router.
3. Provide OIDC configuration via environment variables or by editing `models.OidcConfiguration`.

Example integration:

```python
from fastapi import FastAPI, Request
from ksi_oidc_fastapi.auth_middleware import AuthMiddleware
from ksi_oidc_fastapi.auth_router import router as auth_router
from ksi_oidc_fastapi.models import Role
from typing import Dict, List

app = FastAPI()

ROLE_ROUTES: Dict[Role, List[str]] = {
    Role.PUBLIC: ["/", "/auth/login", "/auth/callback", "/auth/logout"],
    Role.USER: ["/auth/protected", "/docs", "/openapi.json"],
    Role.ADMIN: ["/auth/admin"],
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
  session_cookie_httponly=True,
  session_cookie_secure=True,
  route_configuration=ROLE_ROUTES,
  login_redirect_path="/auth/login",
  role_hierarchy=[Role.PUBLIC, Role.USER, Role.ADMIN],
)

app.include_router(auth_router)

@app.get("/")
async def root(request: Request):
  if getattr(request.state, "is_authenticated", False):
    return {"message": "Hello authenticated user", "user": getattr(request.state, "user", None)}
  return {"message": "Hello anonymous user"}
```

Notes:

- The middleware will set `request.state.session_key`, `request.state.session_data`, `request.state.tokens` and `request.state.is_authenticated`.
- The `user_repository_instance` is optional but recommended: when present the middleware will try to load or create a local user record from the OIDC `sub` claim.

## Configuration

1. Environment variables / `.env` file

   The package reads OIDC configuration from `OidcConfiguration` in `models.py`. The simplest way is to provide a `.env` file at the repository root (pydantic settings are used):

   ```env
   ISSUER=http://localhost:8080/realms/Mordor-2.0
   CLIENT_ID=your-client-id
   CLIENT_SECRET=your-client-secret
   ```

   Other `OidcConfiguration` settings with defaults:

   - `callback_uri` — default: `http://localhost:8081/auth/callback`
   - `post_logout_redirect_uri` — default: `http://localhost:8081`
   - `home_uri` — default: `http://localhost:8081`

2. Routes & role map

   Configure `route_configuration` when creating the middleware. Use the `Role` enum from `models.py` as keys and provide a list of route prefixes that require that role. The middleware uses a role hierarchy to decide access levels.

3. Cookie & session settings

   - `session_cookie_name`, `session_cookie_httponly`, `session_cookie_secure`, and `session_cookie_samesite` are configurable via the middleware constructor.
   - The built-in `SessionManager` is in-memory with a configurable `session_timeout`.

## Token refresh behavior

- Access tokens are checked on each request; if they are near expiry the middleware will attempt to refresh them using the refresh token stored in the session.
- If refresh fails (for example refresh token expired) the user is logged out and the session cleared.

## Production considerations

- Use HTTPS in production and set `session_cookie_secure=True`.
- Replace the in-memory `SessionManager` with a persistent store for multi-instance deployments.
- Provide a concrete `user_repository_instance` to map OIDC `sub` claims to your application's user model.

## Run the example app

Start the FastAPI app with Uvicorn (example):

```powershell
uvicorn your_module:app --port 8081
```

Replace `your_module:app` with the import path for the module that defines `app` in your project.

## Troubleshooting

- If the middleware complains about configuration, verify `.env` and the `OidcConfiguration` values.
- If callback or redirect behaviour is incorrect, check client settings in your OIDC provider and ensure `callback_uri` matches exactly.

---
