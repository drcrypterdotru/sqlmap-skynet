# Global using across UI + runner + MCP
from typing import Set, Optional, Any, Dict, List, Union
from fastapi import WebSocket
from collections import deque
from datetime import datetime


class MonitorState:
    """
    Centralized state management for SQLMAP-SKYNET.

    Features added:
    - Keeps an in-memory ring buffer of recent events (for MCP + debugging)
    - `broadcast()` supports BOTH call styles:
        1) await state.broadcast({"type": "...", "payload": {...}})
        2) await state.broadcast("terminal", {"level": "...", "line": "..."})
    - Tracks last_error + session id for better status responses
    """

    def __init__(self):
        # Runtime status
        self.running: bool = False
        self.runner = None

        # WebSocket clients (WEBASED UI)
        self.ws_clients: Set[WebSocket] = set()

        self.tor_enabled: bool = False
        self.backend_type: str = "sqlmap.py"
        self.rag_enabled: bool = True
        self.web_search_enabled: bool = False
        self.debug_mode: bool = True

       
        self.current_session: Optional[str] = None
        self.last_error: Optional[str] = None

        # Recenting events the lastest and Stores last 500 broadcasts only that
        self._events = deque(maxlen=500)

    # -------------------------
    # Event Buffer (Debug/MCP)
    # -------------------------

    def _record_event(self, msg_type: str, payload: Dict[str, Any]) -> None:
        """Add one event to ring buffer (never throws)."""
        try:
            self._events.append({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "type": msg_type,
                "payload": payload,
            })
        except Exception:
            # Never break runtime because of debug buffer
            pass

    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return most recent events (newest last)."""
        try:
            limit = max(1, min(int(limit), 500))
        except Exception:
            limit = 50
        items = list(self._events)
        return items[-limit:]

    def set_error(self, message: Optional[str]) -> None:
        """Set last_error and record it as an event (safe)."""
        self.last_error = message
        if message:
            self._record_event("error", {"message": message})

    def clear_error(self) -> None:
        self.last_error = None

    # -------------------------
    # WebSocket client helpers
    # -------------------------

    def add_client(self, ws: WebSocket) -> None:
        try:
            self.ws_clients.add(ws)
        except Exception:
            pass

    def remove_client(self, ws: WebSocket) -> None:
        try:
            self.ws_clients.discard(ws)
        except Exception:
            pass

    # -------------------------
    # Broadcast
    # -------------------------

    async def broadcast(
        self,
        message_or_type: Union[Dict[str, Any], str],
        payload: Optional[Dict[str, 
                               Any]] = None
    ) -> None:
        """
        Broadcast message to all connected WebSocket clients.

        Accepts:
          - await state.broadcast({"type": "...", "payload": {...}})
          - await state.broadcast("stats", {...})
        """
        # Normalize into {"type": ..., "payload": ...}
        if isinstance(message_or_type, dict) and payload is None:
            message = message_or_type
            msg_type = str(message.get("type", "unknown"))
            payload = message.get("payload") or {}
        else:
            msg_type = str(message_or_type)
            payload = payload or {}
            message = {"type": msg_type, "payload": payload}

        # Record for MCP/debug visibility
        self._record_event(msg_type, payload)

        # Send to UI clients
        disconnected = set()
        for client in list(self.ws_clients):
            try:
                await client.send_json(message)
            except Exception:
                disconnected.add(client)

        # Cleanner of dead sockets
        self.ws_clients -= disconnected

    # Status helping

    def get_status(self) -> Dict[str, Any]:
        """Basic status for UI/API."""
        return {
            "running": self.running,
            "tor": self.tor_enabled,
            "backend": self.backend_type,
            "rag": self.rag_enabled,
            "web_search": self.web_search_enabled,
            "debug": self.debug_mode,
            "clients": len(self.ws_clients),
            "session": self.current_session,
            "last_error": self.last_error,
        }

    def get_scan_status(self, include_logs: bool = False, logs_limit: int = 50) -> Dict[str, Any]:
        """
        Richer scan status for MCP/debug.
        (Safe to call even when runner is None.)
        """
        runner = getattr(self, "runner", None)

        # Try progress if runner has it
        progress = None
        phase = None
        cycle = None
        max_cycles = None

        if runner is not None:
            progress = getattr(runner, "progress", None)
            ctx = getattr(runner, "context", None)
            if ctx is not None:
                phase = getattr(getattr(ctx, "current_phase", None), "value", None) or getattr(ctx, "current_phase", None)
                cycle = getattr(ctx, "cycle", None)
                max_cycles = getattr(ctx, "max_cycles", None)

        resp: Dict[str, Any] = {
            "running": bool(self.running),
            "has_runner": runner is not None,
            "session": self.current_session,
            "phase": phase,
            "cycle": cycle,
            "max_cycles": max_cycles,
            "progress": progress,
            "last_error": self.last_error,
        }

        if include_logs:
            resp["events"] = self.get_events(logs_limit)

        return resp



state = MonitorState()