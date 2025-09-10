from django.urls.conf import path

from .views import CallbackView, OidcLogoutView

urlpatterns = [
    path("callback/", CallbackView.as_view(), name="ksi_oidc_callback"),
    path("logout/", OidcLogoutView.as_view(), name="ksi_oidc_logout"),
]
