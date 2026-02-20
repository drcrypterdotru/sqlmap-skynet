from typing import Set, Optional, Any, Dict
from fastapi import WebSocket

class MonitorState:
    """Centralized state management for SKYNET"""
    
    def __init__(self):
        self.running = False
        self.ws_clients: Set[WebSocket] = set()
        self.runner = None
        self.tor_enabled = False
        self.backend_type = "sqlmap.py"
        self.rag_enabled = True
        self.web_search_enabled = False
        self.debug_mode = True
        self.current_session = None
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected WebSocket clients"""
        disconnected = set()
        for client in list(self.ws_clients):
            try:
                await client.send_json(message)
            except Exception:
                disconnected.add(client)
        self.ws_clients -= disconnected
    
    def get_status(self) -> Dict:
        """Get current system status"""
        return {
            "running": self.running,
            "tor": self.tor_enabled,
            "backend": self.backend_type,
            "rag": self.rag_enabled,
            "web_search": self.web_search_enabled,
            "clients": len(self.ws_clients),
            "session": self.current_session
        }

 
state = MonitorState()