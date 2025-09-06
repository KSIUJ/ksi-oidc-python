# `ksi-oidc-python`
Libraries for authentication in web applications using OpenID Connect identity providers.

This repo currently contains two packages:
### [`ksi-oidc-django`](./django/README.md)
A Django plugin for OpenID Connect authentication, integrated with the default Django auth backend.

See the library [README.md](./django/README.md) for more details.

### `ksi-oidc-common`
A Python library providing a stateless OpenID Connect client, with support for 
`/.well-known/openid-configuration` discovery.

This library is used as a dependency by `ksi-oidc-django` and contains only the
features needed for the plugin.

The client uses [CZ-NIC/pyoidc](https://github.com/CZ-NIC/pyoidc).
