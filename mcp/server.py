import json
import os
import asyncio
import sys
from typing import Dict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
ROOT = Path(__file__).resolve().parent.parent




# # Core imports with encoding fix for Windows
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
            print(f"[DBG] [{component}] {message}")
            
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

try:
    from mcp.server.fastmcp import FastMCP  # type: ignore
    from mcp.types import TextContent, LoggingLevel  # type: ignore
    from mcp.server.sse import SseServerTransport  # type: ignore
    MCP_AVAILABLE = True
    logger.info("[MCP]", "Official SDK loaded (mcp.server.fastmcp)")
except Exception as e1:
    logger.info("[MCP]", f"Official SDK import failed: {e1}")

# Configuration
MCP_CONFIG = {
    "server_name": "skynet-mcp-server",
    "protocol_version": "2-23-2026",
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
            url: str = "",
            targetlist: str = "", #Target-list .txt
            method: str = "GET",
            data: str = "",
            cookies: str = "",
            headers: str = "",
            max_cycles: int = 30,
            tor: bool = False,
            rag: bool = True,
            web_search: bool = False,
            ai_provider: str = "auto",
            debug: bool = False
        ) -> dict:
            """
            Run SQLMap scan with AI Autonomous.
            """
            if not SQLMapRunner:
                # return json.dumps({"error": "SQLMapRunner not available"}, indent=2)
                return {"ok": False, "error": "SQLMapRunner not available"}
                    
            # Target : url OR targetlist
            def targets_from_files(p: str) -> list[str]:
                fp = Path(p)
                if not fp.is_absolute():
                    fp = (ROOT / fp).resolve()
                else:
                    fp = fp.resolve()

                if ROOT not in fp.parents and fp != ROOT:
                    raise ValueError("targetlist must be inside the project folder")

                if not fp.exists():
                    raise FileNotFoundError(f"targetlist file not found: {fp}")

                lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
                urls: list[str] = []
                seen: set[str] = set()

                for line in lines:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    s = s.rstrip("/")
                    if s not in seen:
                        seen.add(s)
                        urls.append(s)

                return urls

            # Decide targets
            if targetlist and targetlist.strip():
                urls = targets_from_files(targetlist.strip())
            elif url and url.strip():
                urls = [url.strip().rstrip("/")]
            else:
                return {"ok": False, "error": "Provide url or targetlist (.txt)"}

            if not urls:
                return {"ok": False, "error": "No valid targets found"}

            try:
                runner = SQLMapRunner("sqlmap.py")
                state.runner = runner
                state.running = True

                await runner.run_multiple(
                    urls=urls,  # ✅ IMPORTANT
                    method=method,
                    cookies=cookies,
                    max_cycles=max_cycles,
                    data=data,
                    headers=headers,
                    concurrent=1
                )

                result = {
                    "targets_count": len(urls),
                    "first_target": urls[0],
                    "status": runner.results.get("status", "UNKNOWN"),
                    "injection_found": runner.results.get("injection_found", False),
                    "databases": runner.results.get("databases", []),
                    "tables": runner.results.get("tables", {}),
                    "columns_count": len(runner.results.get("columns", {}) or {}),
                    "cycles": runner.results.get("cycles", 0),
                    "timestamp": datetime.now().isoformat(),
                }

                state.running = False
                return {"ok": True, **result}

            except Exception as e:
                state.running = False
                if debug:
                    import traceback
                    return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}
                return {"ok": False, "error": str(e)}
                            

        @self.mcp.tool()
        # async def get_scan_status() -> str:
        #     """Get current scan status"""
        #     try:
        #         runner = getattr(state, "runner", None)
        #         return json.dumps({
        #             "running": bool(getattr(state, "running", False)),
        #             "has_runner": runner is not None,
        #             "progress": getattr(runner, "progress", None) if runner else None,
        #             "results": getattr(runner, "results", None) if runner else None,
        #         }, indent=2)
        #     except Exception as e:
        #         return json.dumps({"error": str(e)}, indent=2)

        @self.mcp.tool()
        async def get_scan_status(include_logs: bool = False, logs_limit: int = 50) -> dict:
           
            try:
                # If your state_manager has the rich method, use it
                if hasattr(state, "get_scan_status"):
                    return state.get_scan_status(include_logs=include_logs, logs_limit=logs_limit)  # type: ignore

                runner = getattr(state, "runner", None)
                resp = {
                    "running": bool(getattr(state, "running", False)),
                    "has_runner": runner is not None,
                    "progress": getattr(runner, "progress", None) if runner else None,
                    "results": getattr(runner, "results", None) if runner else None,
                }

                if include_logs and hasattr(state, "get_events"):
                    resp["events"] = state.get_events(logs_limit)  # type: ignore

                return resp

            except Exception as e:
                return {"ok": False, "error": str(e)}

        @self.mcp.tool()
        # def get_ai_providers() -> str:
        #     """List available AI providers"""
        #     return json.dumps({
        #         "available": [k for k, v in self.cloud_ai_status.items() if v],
        #         "recommended": self._get_recommended_provider()
        #     }, indent=2)
         
        def get_ai_providers() -> dict:
            """List available AI providers"""
            return {
                "available": [k for k, v in self.cloud_ai_status.items() if v],
                "recommended": self._get_recommended_provider()
            }
        # Debug: tool registry size
        try:
            # count = len(getattr(self.mcp, "_tools", {}))
            count = len(self.get_tools_list())
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
mcp = mcp_server.mcp
app = mcp
server = mcp

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

