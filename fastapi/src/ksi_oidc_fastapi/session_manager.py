import time
import secrets
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict

from ksi_oidc_common.tokens import Tokens


@dataclass
class SessionData:
    """Data stored in a user session"""
    user_id: Optional[str] = None
    tokens: Optional[Tokens] = None
    nonce: Optional[str] = None
    oauth_state: Optional[str] = None
    created_at: float = None
    last_accessed: float = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_accessed is None:
            self.last_accessed = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization if needed"""
        return asdict(self)

    def is_expired(self, max_age: int = 300) -> bool:
        """Check if session is expired (default 5 minutes)"""
        return time.time() - self.last_accessed > max_age

    def is_authenticated(self) -> bool:
        """Check if user is authenticated (has valid tokens)"""
        return self.tokens is not None and self.user_id is not None


class SessionManager:
    """In-memory session manager for FastAPI OIDC authentication"""
    
    def __init__(self, session_timeout: int = 300):
        self._sessions: Dict[str, SessionData] = {}
        self.session_timeout = session_timeout
    
    def create_session(self) -> str:
        """Create a new session and return session key"""
        session_key = secrets.token_urlsafe(32)
        self._sessions[session_key] = SessionData()
        return session_key
    
    def get_session(self, session_key: str) -> Optional[SessionData]:
        """Get session data by key"""
        if not session_key:
            return None
            
        session = self._sessions.get(session_key)
        if session is None:
                return None
                

        if session.is_expired(self.session_timeout):
                del self._sessions[session_key]
                return None
                

        session.last_accessed = time.time()
        return session
    
    def update_session(self, session_key: str, **kwargs) -> bool:
        """Update session data"""
        if not session_key:
            return False
        
        session = self._sessions.get(session_key)
        if session is None:
            return False
                
        for key, value in kwargs.items():
            if hasattr(session, key):
                setattr(session, key, value)
                    
        session.last_accessed = time.time()
        return True
    
    def delete_session(self, session_key: str) -> bool:
        """Delete a session"""
        if not session_key:
            return False
            
        
        return self._sessions.pop(session_key, None) is not None
    
    def set_oauth_state(self, session_key: str, state: str, nonce: str) -> bool:
        """Store OAuth state and nonce for CSRF protection"""
        return self.update_session(
            session_key, 
            oauth_state=state, 
            nonce=nonce
        )
    
    def verify_oauth_state(self, session_key: str, received_state: str) -> bool:
        """Verify OAuth state parameter matches stored state"""
        session = self.get_session(session_key)
        if not session or not session.oauth_state:
            return False
        return session.oauth_state == received_state
    
    def set_user_authenticated(self, session_key: str, user_id: str, tokens: Tokens) -> bool:
        """Mark user as authenticated with tokens"""
        return self.update_session(
            session_key,
            user_id=user_id,
            tokens=tokens,
            oauth_state=None,
            nonce=None
        )
    
    def logout_user(self, session_key: str) -> bool:
        """Clear user authentication from session"""
        return self.update_session(
            session_key,
            user_id=None,
            tokens=None,
            oauth_state=None,
            nonce=None
        )
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions and return count of removed sessions"""
        current_time = time.time()
        expired_keys = []
        
        
        for key, session in self._sessions.items():
            if current_time - session.last_accessed > self.session_timeout:
                expired_keys.append(key)
            
        for key in expired_keys:
            del self._sessions[key]
                
        return len(expired_keys)
    
    def get_session_count(self) -> int:
        """Get current number of active sessions"""
        return len(self._sessions)


# Global session manager instance
session_manager = SessionManager()