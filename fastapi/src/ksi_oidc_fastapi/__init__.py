"""
KSI OIDC FastAPI Package

OpenID Connect authentication integration for FastAPI applications.
"""

__version__ = "1.0.0"
__author__ = "opwip-Yaroslav-Kolesnik"

from .auth_middleware import AuthMiddleware
from .auth_router import router as auth_router

__all__ = [
	"AuthMiddleware",
	"auth_router",
]
