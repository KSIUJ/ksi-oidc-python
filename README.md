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

## Using these libraries
The packages in this repo are not published to PyPI.
This is how you can use the Django plugin in your project if you're using `uv` as the package manager:

```toml
[project]
dependencies = [
    "ksi-oidc-django>=x.y.z"
]

[tool.uv.sources]
ksi-oidc-django = { git = "https://github.com/KSIUJ/ksi-oidc-python", subdirectory="django" }
```

You might also want to pin the Git source to a specific tag or commit.

## Disclaimer from the creator
The packages have been created for use in the projects created at KSI.
They are ready-to-use for other projects with similar authentication requirements,
but no guarantees of any kind are made, in particular:
- There are no automatic tests.
- The security has not been audited.
- It's unlikely for the code to receive active maintenance.

It might be desirable to fork this repo or modify its source code in any other way
to make changes with your specific requirements.
Please read the [license](./LICENSE.txt) of this project before doing so.
