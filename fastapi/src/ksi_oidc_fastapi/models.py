class Role:
    PUBLIC = "PUBLIC"
    USER = "USER"
    ADMIN = "admin"

from pydantic_settings import BaseSettings
from typing import List

class OidcConfiguration(BaseSettings):
    issuer : str
    client_id : str
    client_secret : str
    callback_uri : str ="http://localhost:8081/auth/callback"
    post_logout_redirect_uri : str ="http://localhost:8081"
    home_uri : str ="http://localhost:8081"
    login_requested_scopes : List[str] = ["profile","email", "roles"]
    class Config:
        env_file = ".env"
        _case_sensitive = False
    
    
OidcConf = OidcConfiguration()
