from enum import Enum

class Role(str, Enum):
    PUBLIC = "PUBLIC"
    USER = "USER"
    ADMIN = "admin"