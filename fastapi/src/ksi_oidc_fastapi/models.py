class Role:
    PUBLIC = "PUBLIC"
    USER = "USER"
    ADMIN = "admin"
    
    @classmethod
    def get_all_roles(cls) -> list[str]:
        """
        Get all available roles.
        
        Returns:
            List of role values
        """
        return [
            getattr(cls, attr) 
            for attr in dir(cls) 
            if not attr.startswith('_') and not callable(getattr(cls, attr))
        ]
    
    @classmethod
    def add_role(cls, role_name: str, role_value: str = None) -> None:
        """
        Add a new role to the Role class.
        
        Args:
            role_name: The attribute name for the role (e.g., "MANAGER")
            role_value: The value for the role (defaults to role_name if not provided)
        
        Raises:
            ValueError: If role already exists
        """
        role_name = role_name.upper()
        
        if hasattr(cls, role_name):
            raise ValueError(f"Role '{role_name}' already exists")
        
        if role_value is None:
            role_value = role_name
        
        setattr(cls, role_name, role_value)
    
    @classmethod
    def remove_role(cls, role_name: str) -> None:
        """
        Remove a role from the Role class.
        
        Args:
            role_name: The attribute name of the role to remove
        
        Raises:
            ValueError: If role doesn't exist
        """
        role_name = role_name.upper()
        
        if not hasattr(cls, role_name):
            raise ValueError(f"Role '{role_name}' does not exist")
        
        delattr(cls, role_name)
    
    @classmethod
    def edit_role(cls, role_name: str, new_value: str) -> None:
        """
        Edit an existing role.
        
        Args:
            role_name: The attribute name of the role to edit
            new_value: The new value for the role(keycloak name)
        
        Raises:
            ValueError: If role doesn't exist
        """
        role_name = role_name.upper()
        
        if not hasattr(cls, role_name):
            raise ValueError(f"Role '{role_name}' does not exist")
        
        setattr(cls, role_name, new_value)

from pydantic_settings import BaseSettings
from typing import List

class OidcConfiguration(BaseSettings):
    issuer : str
    client_id : str
    client_secret : str
    callback_uri : str 
    post_logout_redirect_uri : str 
    home_uri : str 
    login_requested_scopes : List[str] = ["profile","email", "roles"]
    class Config:
        env_file = ".env"
        _case_sensitive = False
    
    
OidcConf = OidcConfiguration()
