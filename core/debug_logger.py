
#Debug Logger Module => Cyan/Green Debug System with Easy Color Control 
import sys
import traceback
import json
from datetime import datetime
from typing import Optional, Any, Dict
from enum import Enum

# Import config
import config
from datetime import datetime
import os

 
class ColorCode(Enum):
    # Easy color control enum 
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"


class DebugLogger:
    # Advanced debug logger with color coding and MCP integration 
    
    def __init__(self, name: str = "SKYNET"):
        self.name = name
        self.enabled = config.DEBUG_CONFIG["enabled"]
        self.colors = config.DEBUG_CONFIG["colors"]
        self.timestamp_format = config.DEBUG_CONFIG["timestamp_format"]
        self.mcp_mode = False
        self.use_icons = True  # Enable emoji/icons for better visibility
        self.compact_mode = False  # Set True for compact output
        
        # Color mapping for easy access
        self.color_map = {
            'cyan': ColorCode.CYAN,
            'green': ColorCode.GREEN,
            'yellow': ColorCode.YELLOW,
            'red': ColorCode.RED,
            'magenta': ColorCode.MAGENTA,
            'blue': ColorCode.BLUE,
            'white': ColorCode.WHITE,
            'bold': ColorCode.BOLD,
            'dim': ColorCode.DIM,
            'reset': ColorCode.RESET
        }
        
        # Icons for different log types
        self.icons = {
            'debug': '🔍',
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌',
            'mcp': '🔄',
            'ai': '🧠',
            'rag': '📚',
            'scan': '🎯',
            'db': '🗄️',
            'waf': '🛡️',
            'file': '📁',
            'network': '🌐',
            'time': '⏱️'
        }
        
    def _get_timestamp(self) -> str:
        # Get formatted timestamp 
        return datetime.now().strftime(self.timestamp_format)[:-3]
    
    def _colorize(self, text: str, color: str) -> str:
        # Easy color wrapper 
        if color in self.color_map:
            return f"{self.color_map[color].value}{text}{ColorCode.RESET.value}"
        return text
    
    def _format_message(self, level: str, component: str, message: str, 
                       color: str, icon: Optional[str] = None) -> str:
        # Format message with colors and optional icon 
        ts = self._get_timestamp()
        color_code = self.colors.get(color, "")
        reset = self.colors["reset"]
        
        # Build icon string
        icon_str = ""
        if self.use_icons and icon:
            icon_str = f"{icon} "
        
        # Format based on compact mode
        if self.compact_mode:
            return f"{color_code}[{ts}] [{level}] {icon_str}{message}{reset}"
        else:
            # Full format with component
            component_colored = self._colorize(f"[{component}]", "dim")
            return f"{color_code}[{ts}]{reset} {component_colored} {color_code}{icon_str}{message}{reset}"
    
    # === Easy Color Methods ===
    def cyan(self, text: str) -> str:
        #Return cyan colored text 
        return self._colorize(text, 'cyan')
    
    def green(self, text: str) -> str:
        #Return green colored text 
        return self._colorize(text, 'green')
    
    def yellow(self, text: str) -> str:
        #Return yellow colored text
        return self._colorize(text, 'yellow')
    
    def red(self, text: str) -> str:
        #Return red colored text
        return self._colorize(text, 'red')
    
    def magenta(self, text: str) -> str:
        #Return magenta colored text
        return self._colorize(text, 'magenta')
    
    def bold(self, text: str) -> str:
        #Return bold text
        return self._colorize(text, 'bold')
    
    # === Standard Logging Methods ===
    def debug(self, component: str, message: str, data: Optional[Any] = None):
        #Cyan debug messages for detailed tracing
        if not self.enabled:
            return
        
        formatted = self._format_message("DEBUG", component, message, "cyan", self.icons['debug'])
        print(formatted, file=sys.stderr if self.mcp_mode else sys.stdout)
        
        if data:
            data_str = json.dumps(data, indent=2, default=str) if isinstance(data, dict) else str(data)
            lines = data_str.split('\n')[:5]  # Limit to 5 lines
            for line in lines:
                print(f"{self.cyan('  │ ')}{line[:20000]}")
            if len(data_str.split('\n')) > 5:
                print(f"{self.cyan('  │ ')}... ({len(data_str.split('\n')) - 5} more lines)")

    def info(self, component: str, message: str, data: Optional[Any] = None):
        #Green info messages for general status
        if not self.enabled:
            return
        
        formatted = self._format_message("INFO", component, message, "green", self.icons['info'])
        print(formatted)
        
        if data:
            print(f"{self.green('  ↳')} {str(data)[:200]}")

    def success(self, component: str, message: str, data: Optional[Any] = None):
        #Bright green success messages
        formatted = self._format_message("SUCCESS", component, message, "green", self.icons['success'])
        # Make it bold green for success
        print(f"\033[1m{formatted}\033[0m")
        
        if data:
            print(f"{self.green('  ✓')} {str(data)[:200]}")

    def warning(self, component: str, message: str, data: Optional[Any] = None):
        #Yellow warning messages
        formatted = self._format_message("WARN", component, message, "yellow", self.icons['warning'])
        print(formatted, file=sys.stderr)
        
        if data:
            print(f"{self.yellow('  ⚡')} {str(data)[:200]}", file=sys.stderr)

    def error(self, component: str, message: str, exc_info: bool = False, data: Optional[Any] = None):
        #Red error messages with optional traceback
        formatted = self._format_message("ERROR", component, message, "red", self.icons['error'])
        print(formatted, file=sys.stderr)
        
        if data:
            print(f"{self.red('  ✗')} {str(data)[:200]}", file=sys.stderr)
        
        if exc_info:
            print(f"{self.red('  Traceback:')}")
            traceback.print_exc()

    # === Specialized Logging Methods ===
    def mcp_log(self, direction: str, message_type: str, data: Optional[Any] = None):
        # MCP protocol logging with better formatting
        icon = self.icons['mcp']
        color = "magenta" if direction == "SEND" else "cyan"
        
        # Format direction with arrow
        arrow = "➡️ " if direction == "SEND" else "⬅️ "
        
        formatted = self._format_message(
            f"MCP-{direction}", 
            "MCP", 
            f"{arrow}{message_type}", 
            color,
            icon
        )
        print(formatted)
        
        if data:
            # Pretty print JSON data for MCP
            try:
                if isinstance(data, dict):
                    json_str = json.dumps(data, indent=2, default=str)
                    lines = json_str.split('\n')[:10]
                    for line in lines:
                        print(f"{self.color_map[color].value}  │ {line}{ColorCode.RESET.value}")
                    if len(json_str.split('\n')) > 10:
                        print(f"{self.color_map[color].value}  │ ... ({len(json_str.split('\n')) - 10} more lines){ColorCode.RESET.value}")
                else:
                    preview = str(data)[:150] + "..." if len(str(data)) > 150 else str(data)
                    print(f"{self.color_map[color].value}  ↳ {preview}{ColorCode.RESET.value}")
            except:
                preview = str(data)[:150]
                print(f"{self.color_map[color].value}  ↳ {preview}{ColorCode.RESET.value}")

    def mcp_connect(self, endpoint: str):
        #Log MCP connection establishment 
        print(f"\n{self.cyan('═' * 60)}")
        print(f"{self.cyan('  🔌 MCP Connection Established')}")
        print(f"{self.cyan('  Endpoint:')} {endpoint}")
        print(f"{self.cyan('═' * 60)}\n")

    def ai_thought(self, cycle: int, thought: str, model: str = "default"):
        #AI decision logging with model info 
        icon = self.icons['ai']
        model_str = f"[{model}]" if model != "default" else ""
        
        formatted = self._format_message(
            f"AI-C{cycle}", 
            "NEURAL", 
            f"{model_str} {thought}", 
            "green",
            icon
        )
        print(formatted)

    def rag_query(self, query: str, results_count: int, similarity: float = 0.0):
        #Enhanced RAG memory query logging 
        icon = self.icons['rag']
        sim_str = f" (sim: {similarity:.2f})" if similarity > 0 else ""
        
        msg = f"Query: '{query[:50]}...'{sim_str} | Results: {results_count}"
        formatted = self._format_message("RAG", "MEMORY", msg, "cyan", icon)
        print(formatted)

    def scan_status(self, target: str, status: str, progress: float = 0.0):
        #Scan status with progress bar 
        icon = self.icons['scan']
        bar_width = 20
        filled = int(bar_width * progress)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        color = "green" if status == "COMPLETE" else "cyan" if status == "SCANNING" else "yellow"
        
        formatted = self._format_message(
            "SCAN", 
            "TARGET", 
            f"{target[:30]} [{bar}] {progress*100:.1f}% - {status}", 
            color,
            icon
        )
        print(formatted)

    def db_found(self, db_name: str, tables_count: int = 0):
        #Database discovery logging 
        icon = self.icons['db']
        msg = f"Database: {db_name}"
        if tables_count > 0:
            msg += f" ({tables_count} tables)"
        
        formatted = self._format_message("DB", "SCHEMA", msg, "green", icon)
        print(f"\033[1m{formatted}\033[0m")  # Bold for emphasis

    def waf_detected(self, waf_type: str, confidence: float = 0.0):
        # WAF detection logging 
        icon = self.icons['waf']
        conf_str = f" ({confidence*100:.0f}%)" if confidence > 0 else ""
        
        formatted = self._format_message(
            "WAF", 
            "SECURITY", 
            f"Detected: {waf_type}{conf_str}", 
            "yellow",
            icon
        )
        print(f"{self.yellow('⚠️ ')}{formatted}")

    def file_operation(self, operation: str, filepath: str, details: Optional[str] = None):
        # File operation logging 
        icon = self.icons['file']
        formatted = self._format_message(
            "FILE", 
            "IO", 
            f"{operation}: {filepath}", 
            "blue",
            icon
        )
        print(formatted)
        
        if details:
            print(f"{self.blue('  📄')} {details}")

    def network_request(self, method: str, url: str, status: Optional[int] = None):
        # Network request logging 
        icon = self.icons['network']
        status_str = f" -> {status}" if status else ""
        color = "green" if status and 200 <= status < 300 else "red" if status and status >= 400 else "cyan"
        
        formatted = self._format_message(
            "NET", 
            "HTTP", 
            f"{method} {url[:50]}{status_str}", 
            color,
            icon
        )
        print(formatted)

    def timing(self, operation: str, elapsed_ms: float):
        # Timing information 
        icon = self.icons['time']
        color = "green" if elapsed_ms < 1000 else "yellow" if elapsed_ms < 5000 else "red"
        
        formatted = self._format_message(
            "TIME", 
            "PERF", 
            f"{operation}: {elapsed_ms:.2f}ms", 
            color,
            icon
        )
        print(formatted)

    # === Utility Methods ===
    def banner(self, title: str, width: int = 60):
        # Print a banner 
        print(f"\n{self.cyan('╔' + '═' * (width - 2) + '╗')}")
        print(f"{self.cyan('║')}{self.bold(title.center(width - 2))}{self.cyan('║')}")
        print(f"{self.cyan('╚' + '═' * (width - 2) + '╝')}\n")

    def section(self, title: str):
        # Print a section header 
        print(f"\n{self.green('─' * 60)}")
        print(f"{self.green('  ▶ ')}{self.bold(title)}")
        print(f"{self.green('─' * 60)}")

    def divider(self, char: str = '─'):
        # Print a divider line 
        print(self.color_map.get('dim', ColorCode.DIM).value + char * 60 + ColorCode.RESET.value)

    def json_pretty(self, data: Dict, title: Optional[str] = None):
        #Pretty print JSON with colors 
        if title:
            print(f"{self.cyan(title)}")
        
        json_str = json.dumps(data, indent=2, default=str)
        # Add syntax highlighting
        lines = json_str.split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                print(f"{self.cyan(key)}:{self.green(value)}")
            else:
                print(line)

    def table(self, headers: list, rows: list):
  
        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        
        
        header_line = " | ".join(self.bold(h.ljust(w)) for h, w in zip(headers, widths))
        print(f"\n{self.cyan(header_line)}")
        print(self.cyan("-" * len(header_line)))
        
         
        for row in rows:
            row_line = " | ".join(str(cell).ljust(w) for cell, w in zip(row, widths))
            print(f"{self.green(row_line)}")
        print()

 
logger = DebugLogger()