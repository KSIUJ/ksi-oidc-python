# ksi-oidc-django

## About this package
This package adds OpenID Connect authentication functionality for Django projects.

### Features:
- Autoconfiguration via the `/.well-known/openid-configuration` endpoint
- Support for refresh tokens
    - The session duration is limited by the expiration time of the refresh token
    - The authentication middleware that the user always has a valid access token and refreshes it when it has expired
- SSO sessions:
  - Checking for an active SSO session using a redirection to the authentication endpoint with `prompt=none`
  - Endpoint for ending the SSO session and logging out from Django
  - (*Planned*) Back-channel logout
- Support for disabling the `OidcAuthBackend` in the settings file without requiring other changes to the views
- Syncing of user groups and staff/superuser status based on the `realm_access.roles` claim in the access token
- Custom `@ksi_oidc_login_required` and `@ksi_oidc_check_sso` view decorators

## Notice
The source code of this library incorporates modified source code from the [mozilla-django-oidc] library.
The fragments based on [mozilla-django-oidc] are appropriately marked in comments in the source code.
[mozilla-django-oidc] is licenced under the **Mozilla Public License 2.0**, available 
[here](https://github.com/mozilla/mozilla-django-oidc/blob/main/LICENSE).

[mozilla-django-oidc]: https://github.com/mozilla/mozilla-django-oidc

## Configuration
In the appropriate Django setting files:

1. Add `django.contrib.auth` (if not yet added) and `ksi_oidc_django` to `INSTALLED_APPS`.

    It is required for adding the models for this library when running `manage.py migrate`
    and provides extra configuration checks.
    ```python
    INSTALLED_APPS = [
        # ...
        'django.contrib.auth',
        # ...
        'ksi_oidc_django',
        # ...
    ]
    ```

2. Add the `OidcAuthMiddleware` to `MIDDLEWARE`:

    It must be placed __directly after__ Django's `AuthenticationMiddleware`, 
    because it is required for the session expiry and refresh logic to work.
    If any other middleware was added in between `AuthenticationMiddleware` and `OidcAuthMiddleware`,
    the `request.user` might be a user whose session has expired while processing that middleware.

    See [the Middleware Ordering section in the Django docs](https://docs.djangoproject.com/en/5.2/ref/middleware/#middleware-ordering)
    for a standard order of other middleware.
    ```python
    MIDDLEWARE = [
        # ...
        'django.contrib.sessions.middleware.SessionMiddleware',
        # ...
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'ksi_oidc_django.middleware.OidcAuthMiddleware',
        # ...
    ]
    ```

3. Add `ksi_oidc_django`-specific settings:
 
    ```python
    # TODO: Use flat config for these
    OIDC_AUTH_PROVIDER = {   
        # Set user's Django groups to the roles from the access token claims.
        # Note that this will also remove the user from the groups that are not present in the access token.
        'sync_roles_as_groups': False,

        # Sets or unsets the User.is_staff and User.is_superuser fields
        # if the access token contains claims for these roles.
        # Set to None to disable this feature.
        'staff_role': 'ksi-admin',
        'superuser_role': 'ksi-admin',
    }
    OIDC_AUTH_SSO_CHECK_COOLDOWN_SECONDS = 300
    ```

4. Add `OidcAuthBackend` to `AUTHENTICATION_BACKENDS`:
    
    ```python
    AUTHENTICATION_BACKENDS = (
        # This is the standard Django backend, you can remove it if you only use
        # OpenID Connect for authentication.
        'django.contrib.auth.backends.ModelBackend',
        'ksi_oidc_django.backends.OidcAuthBackend',
    )
    ```
   
    You can disable the `OidcAuthBackend` without removing the app and middleware.
    The middleware will detect that the backend is not enabled and raise [`MiddlewareNotUsed`].

5. Use the `manage.py oidc_set_issuer` and `manage.py oidc_init_dynamic`/`manage.py oidc_init_static` commands
    to configure the OpenID Connect client.

### Views configuration
Add these entries in your `urls.py`:
```python
urlpatterns = [
    # ...
    
    path('login/', OidcLoginView.as_view(), name='login'),
    
    # Register the endpoints `/oidc/callback/` and `/oidc/logout/`:
    path('oidc/', include('ksi_oidc_django.urls')),
]
```
You may change the paths. Make sure to set the setting [`LOGIN_URL`] to the path of the login page.
`ksi-oidc-django` also uses the standard [`LOGOUT_REDIRECT_URL`] setting, set it to the path
you want the user to be redirected to after logging out.

In the settings of your OIDC provider you will need to add the `/oidc/callback/` URL as a valid redirect URL
and the [`LOGOUT_REDIRECT_URL`] URL as a valid post logout redirect URL.

`OidcLoginView` redirects the user to the OIDC provider's login page if the `OidcAuthBackend` is enabled.
If it's not, it uses the view specified in `OidcLoginView.fallback_view` to render the login page.
It uses [`DjangoLoginView`] by default. You can use a different view for this by specifying the `fallback_view`
when calling `.as_view()`:

```python
urlpatterns = [
    # ...
    path('login/', OidcLoginView.as_view(fallback_view=MyFallbackLoginView.as_view()), name='login'),
    # ...
]
```

## Custom decorators
`ksi-oidc-django` provides these new view decorators:

- `@ksi_oidc_login_required` performs the same check as Django's `@login_required`,
    but if the user is not logged in, it redirects the user directly to the OIDC login page
    (if the `OidcAuthBackend` is enabled).
    
    If you were to use `@login_required` instead, accessing a protected view would redirect the user twice,
    first to the `LOGIN_URL`, which would then redirect the user to the OIDC login page.

- `@ksi_oidc_check_sso` is used for views that do not require authentication.
    When an unauthenticated user tries to access a view decorated with `@ksi_oidc_check_sso`,
    they will be redirected to the OIDC authentication endpoint with `prompt=none`,
    to check if the user already has an active SSO session.

    The `OIDC_AUTH_SSO_CHECK_COOLDOWN_SECONDS` setting controls the minimum time between such checks.

[`LOGIN_URL`]: https://docs.djangoproject.com/en/5.2/ref/settings/#login-url
[`LOGOUT_REDIRECT_URL`]: https://docs.djangoproject.com/en/5.2/ref/settings/#logout-redirect-url
[`MiddlewareNotUsed`]: https://docs.djangoproject.com/en/5.2/topics/http/middleware/#marking-middleware-as-unused.
[`DjangoLoginView`]: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.views.LoginView
