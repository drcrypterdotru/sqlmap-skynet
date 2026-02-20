"""
MCP Server with Automatic Fallback
Uses official SDK if available, otherwise uses compatible mock / inline MCP
"""

import json
import os
import asyncio
import sys
import re
from typing import Dict
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try official MCP SDK first, then newer/alternate layouts, then fall back.
# Keep console noise low by default. Set MCP_DEBUG=1 to see detailed import errors.
_MCP_DEBUG = os.getenv("MCP_DEBUG", "").strip() in ("1", "true", "yes", "on")

def _mcp_debug(msg: str):
    if _MCP_DEBUG:
        print(msg)

MCP_AVAILABLE = False

# 1) Official MCP Python SDK (FastMCP 1.x) layout
try:
    from mcp.server.fastmcp import FastMCP  # type: ignore
    from mcp.types import TextContent, LoggingLevel  # type: ignore
    from mcp.server.sse import SseServerTransport  # type: ignore
    MCP_AVAILABLE = True
    _mcp_debug("[MCP] ✅ Official SDK loaded (mcp.server.fastmcp)")
except Exception as e1:
    _mcp_debug(f"[MCP] ⚠️ Official SDK import failed: {e1!r}")

    # 2) Alternate layout seen in some guides
    try:
        from mcp.server import FastMCP  # type: ignore
        try:
            from mcp.types import TextContent, LoggingLevel  # type: ignore
        except Exception:
            TextContent = None  # type: ignore
            LoggingLevel = None  # type: ignore

        try:
            from mcp.server.sse import SseServerTransport  # type: ignore
        except Exception:
            SseServerTransport = None  # type: ignore

        MCP_AVAILABLE = True
        _mcp_debug("[MCP] ✅ SDK loaded (mcp.server)")
    except Exception as e2:
        _mcp_debug(f"[MCP] ⚠️ mcp.server import failed: {e2!r}")

        # 3) FastMCP standalone package (common in newer ecosystem)
        try:
            from fastmcp import FastMCP  # type: ignore
            TextContent = None  # type: ignore
            LoggingLevel = None  # type: ignore
            SseServerTransport = None  # type: ignore
            MCP_AVAILABLE = True
            _mcp_debug("[MCP] ✅ FastMCP loaded (fastmcp)")
        except Exception as e3:
            _mcp_debug(f"[MCP] ⚠️ fastmcp import failed: {e3!r}")

# 4) Project-local mock implementation (optional)
if not MCP_AVAILABLE:
    try:
        from mock_mcp import FastMCP, TextContent, LoggingLevel, SseServerTransport  # type: ignore
        MCP_AVAILABLE = True
        _mcp_debug("[MCP] ✅ Project mock MCP loaded (mock_mcp)")
    except Exception as e4:
        _mcp_debug(f"[MCP] ⚠️ mock_mcp import failed: {e4!r}")

# 5) Minimal inline implementation (always available)
if not MCP_AVAILABLE:
    _mcp_debug("[MCP] 🔄 Using inline minimal implementation")

    class TextContent:
        def __init__(self, text: str):
            self.type = "text"
            self.text = text

    class LoggingLevel:
        DEBUG = "debug"
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"

    class FastMCP:
        def __init__(self, name: str):
            self.name = name
            self._tools = {}
            self._resources = {}
            self._mcp_server = self

        def tool(self):
            def decorator(func):
                self._tools[func.__name__] = func
                return func
            return decorator

        def resource(self, uri: str):
            def decorator(func):
                self._resources[uri] = func
                return func
            return decorator

        async def call_tool(self, name: str, arguments: Dict) -> str:
            if name not in self._tools:
                return json.dumps({"error": f"Tool '{name}' not found"})
            try:
                func = self._tools[name]
                result = await func(**arguments) if asyncio.iscoroutinefunction(func) else func(**arguments)
                return result if isinstance(result, str) else json.dumps(result)
            except Exception as e:
                return json.dumps({"error": str(e)})

        def get_tools_list(self):
            return list(self._tools.keys())

    class SseServerTransport:
        def __init__(self, endpoint: str):
            self.endpoint = endpoint

    MCP_AVAILABLE = True
    _mcp_debug("[MCP] ✅ Inline implementation loaded")

# Core imports with encoding fix for Windows
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

try:
    from core.debug_logger import logger
except ImportError:
    class SimpleLogger:
        def info(self, component, message): 
            print(f"[INFO] [{component}] {message}")
        def error(self, component, message): 
            print(f"[ERROR] [{component}] {message}")
        def warning(self, component, message): 
            print(f"[WARN] [{component}] {message}")
        def debug(self, component, message): 
            pass
    logger = SimpleLogger()

try:
    from core.rag_memory import rag_memory
except ImportError:
    rag_memory = None

try:
    from core.state_manager import state
except ImportError:
    class MockState:
        running = False
        runner = None
    state = MockState()

try:
    from scanners.runner import SQLMapRunner
except ImportError:
    SQLMapRunner = None

# Configuration
MCP_CONFIG = {
    "server_name": "skynet-mcp-server",
    "protocol_version": "2024-11-05",
    "max_retries": 3,
    "timeout": 300
}

class SkynetMCPServer:
    """MCP Server with fallback support"""

    def __init__(self):
        self.mcp = None
        self.sse_transport = None
        self.tools = {}
        self.resources = {}
        self.runner = None
        self.cloud_ai_status = self._check_cloud_ai()
        self._init_mcp()

    def _check_cloud_ai(self) -> Dict[str, bool]:
        """Check which cloud AI providers are available"""
        providers = {
            'openai': bool(os.getenv('OPENAI_API_KEY')),
            'claude': bool(os.getenv('ANTHROPIC_API_KEY')),
            'deepseek': bool(os.getenv('DEEPSEEK_API_KEY')),
            'groq': bool(os.getenv('GROQ_API_KEY')),
            'kimi': bool(os.getenv('KIMI_API_KEY')),
            'ollama': False
        }

        # Check Ollama
        try:
            import subprocess
            result = subprocess.run(['ollama', 'list'], capture_output=True, timeout=5)
            providers['ollama'] = result.returncode == 0
        except Exception:
            pass

        enabled = [k for k, v in providers.items() if v]
        # FIX: Use two arguments instead of one f-string
        logger.info("MCP", f"Cloud AI providers available: {enabled}")
        return providers

    def _init_mcp(self):
        """Initialize MCP server"""
        try:
            self.mcp = FastMCP(MCP_CONFIG["server_name"])

            # SSE transport is optional (depends on SDK/layout). Keep None if unavailable.
            if callable(globals().get("SseServerTransport", None)):
                try:
                    self.sse_transport = SseServerTransport("/mcp/v1/message")
                except Exception:
                    self.sse_transport = None
            else:
                self.sse_transport = None

            self._register_tools()
            self._register_resources()
            # FIX: Use two arguments
            logger.info("MCP", f"Server initialized: {MCP_CONFIG['server_name']}")
        except Exception as e:
            # FIX: Use two arguments
            logger.error("MCP", f"Failed to initialize: {e}")
            self.mcp = None

    def _register_tools(self):
        """Register MCP tools"""
        if not self.mcp:
            return

        @self.mcp.tool()
        async def sqlmap_scan(
            url: str,
            method: str = "GET",
            data: str = "",
            cookies: str = "",
            headers: str = "",
            max_cycles: int = 30,
            tor: bool = False,
            rag: bool = True,
            web_search: bool = False,
            ai_provider: str = "auto"
        ) -> str:
            """
            Run SQLMap scan with AI enhancement.
            """
            if not SQLMapRunner:
                return json.dumps({"error": "SQLMapRunner not available"}, indent=2)

            try:
                runner = SQLMapRunner("sqlmap.py")
                state.runner = runner
                state.running = True

                if ai_provider != "auto":
                    # Keep your custom logic if runner.ai exists
                    try:
                        runner.ai.cloud_ai.available_providers = (
                            [ai_provider]
                            if ai_provider in runner.ai.cloud_ai.available_providers
                            else runner.ai.cloud_ai.available_providers
                        )
                    except Exception:
                        pass

                await runner.run_multiple(
                    urls=[url],
                    method=method,
                    cookies=cookies,
                    max_cycles=max_cycles,
                    data=data,
                    headers=headers,
                    concurrent=1
                )

                result = {
                    "target": runner.results.get('target', url),
                    "status": runner.results.get('status', 'UNKNOWN'),
                    "injection_found": runner.results.get('injection_found', False),
                    "databases": runner.results.get('databases', []),
                    "tables": runner.results.get('tables', {}),
                    "columns_count": len(runner.results.get('columns', {})),
                    "cycles": runner.results.get('cycles', 0),
                    "timestamp": datetime.now().isoformat()
                }

                state.running = False
                return json.dumps(result, indent=2)

            except Exception as e:
                state.running = False
                return json.dumps({"error": str(e)}, indent=2)

        @self.mcp.tool()
        async def get_scan_status() -> str:
            """Get current scan status"""
            try:
                runner = getattr(state, "runner", None)
                return json.dumps({
                    "running": bool(getattr(state, "running", False)),
                    "has_runner": runner is not None,
                    "progress": getattr(runner, "progress", None) if runner else None,
                    "results": getattr(runner, "results", None) if runner else None,
                }, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)}, indent=2)

        @self.mcp.tool()
        def get_ai_providers() -> str:
            """List available AI providers"""
            return json.dumps({
                "available": [k for k, v in self.cloud_ai_status.items() if v],
                "recommended": self._get_recommended_provider()
            }, indent=2)

        # Debug: tool registry size
        try:
            count = len(getattr(self.mcp, "_tools", {}))
        except Exception:
            count = 0
        # FIX: Use two arguments
        logger.info("MCP", f"Registered {count} tools")

    def _register_resources(self):
        """Register MCP resources"""
        if not self.mcp:
            return

        @self.mcp.resource("memory://sessions")
        def get_memory() -> str:
            """Get memory sessions resource"""
            if not rag_memory:
                return json.dumps({"error": "RAG memory not available"})
            sessions = rag_memory.get_all_sessions()
            return json.dumps(sessions, indent=2)

        @self.mcp.resource("config://ai-status")
        def get_ai_status() -> str:
            """Get AI provider status"""
            return json.dumps(self.cloud_ai_status, indent=2)

    def _get_recommended_provider(self) -> str:
        """Get the best available AI provider"""
        priority = ['claude', 'openai', 'deepseek', 'groq', 'kimi', 'ollama']
        for provider in priority:
            if self.cloud_ai_status.get(provider):
                return provider
        return "none"

    def get_tools_list(self) -> list:
        """Get list of available tools"""
        if self.mcp and hasattr(self.mcp, "get_tools_list"):
            return self.mcp.get_tools_list()
        if self.mcp and hasattr(self.mcp, "_tools"):
            return list(self.mcp._tools.keys())
        return []

    async def test_tool(self, name: str, args: dict = None):
        """Test a tool by name"""
        if not self.mcp or not hasattr(self.mcp, "call_tool"):
            return "MCP not initialized"

        args = args or {}
        return await self.mcp.call_tool(name, args)

 
mcp_server = SkynetMCPServer()

# # Test if run directly
# if __name__ == "__main__":
#     print("\n" + "="*60)
#     print("MCP SERVER TEST")
#     print("="*60)

#     print(f"\nMCP Available: {MCP_AVAILABLE}")
#     print(f"Server: {mcp_server.mcp is not None}")
#     print(f"Tools: {mcp_server.get_tools_list()}")
#     print(f"Cloud AI: {mcp_server.cloud_ai_status}")

#     async def test():
#         result = await mcp_server.test_tool("get_scan_status")
#         print(f"\nTest result: {result}")

#     asyncio.run(test())