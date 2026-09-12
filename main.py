# MCP Serve: A Powerful Server for Deep Learning Models

import os
import re
import subprocess
from mcp.server.fastmcp import FastMCP
from starlette.exceptions import HTTPException
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MCP API key
APP_NAME = os.getenv("APP_NAME", 'Terminal')
APP_DEBUG = os.getenv("APP_DEBUG", True)
APP_LOG_LEVEL = os.getenv("APP_LOG_LEVEL", 'DEBUG')
APP_PORT = os.getenv("APP_PORT", 8005)
MCP_API_KEY = os.getenv("MCP_API_KEY", 'test1234')

# --- Hardening: command allowlist + shell-injection defense ---
# A bare `subprocess.check_output(command, shell=True)` with no allowlist lets any
# caller run arbitrary commands. We gate on an allowlist of safe inspection commands
# and reject shell metacharacters/operators that enable injection (CWE-78).
_SHELL_METACHARS = re.compile(r'[;&|<>`$(){}!\[\]\n\r]|\$\(|`')
# Commands that are safe to expose for inspection/diagnostics.
_ALLOWED_COMMANDS = {
    'ls', 'cat', 'head', 'tail', 'grep', 'find', 'diff', 'wc', 'sort',
    'uniq', 'cut', 'tr', 'stat', 'file', 'realpath', 'echo', 'pwd',
}


def _validate_command(command: str) -> str:
    """Validate a shell command against the allowlist + metachar rejection.

    Returns the validated command name (first token). Raises ValueError on any
    rejected input. This is the gate that prevents unauthenticated arbitrary
    command execution via the `shell_command` MCP tool.
    """
    if not command or not command.strip():
        raise ValueError("empty command")
    command = command.strip()
    # Reject shell metacharacters / substitution / control operators.
    if _SHELL_METACHARS.search(command):
        raise ValueError(
            f"command rejected: contains shell metacharacters/operators "
            f"(semicolons, pipes, backticks, $(), redirects, etc.)"
        )
    parts = command.split()
    cmd_name = parts[0]
    # Allowlist: only the bare command name, no path traversal.
    if cmd_name not in _ALLOWED_COMMANDS:
        raise ValueError(
            f"command rejected: '{cmd_name}' is not in the allowlist "
            f"(allowed: {sorted(_ALLOWED_COMMANDS)})"
        )
    # Reject path-like trickery (../../bin/sh, /usr/bin/cat, ./cat).
    if '/' in cmd_name or cmd_name.startswith('.'):
        raise ValueError("command rejected: path-like command names are not permitted")
    return cmd_name


# Middleware function to check API key authentication
def middleware(request):
    # Verify the x-api-key header matches the environment variable
    if request.headers.get("x-api-key") != MCP_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# Server configuration settings
settings = {
    'debug': APP_DEBUG,          # Enable debug mode
    'port': APP_PORT,            # Port to run server on
    'log_level': APP_LOG_LEVEL,  # Logging verbosity
    # 'middleware': middleware, # Authentication middleware
}

# Initialize FastMCP server instance
mcp = FastMCP(name=APP_NAME, **settings)

@mcp.tool()
async def shell_command(command: str) -> str:
    """Execute a allowlisted shell command for inspection/diagnostics.

    Only safe read/inspection commands (ls, cat, head, tail, grep, find, wc,
    sort, uniq, cut, tr, stat, file, realpath, echo, pwd) are permitted. Shell
    metacharacters and operators (;, |, &, <, >, `, $, (), {}, !, [], newlines)
    are rejected to prevent command injection (CWE-78).
    """
    _validate_command(command)
    return subprocess.check_output(command, shell=True).decode()

if __name__ == "__main__":
    print(f"Starting MCP server... {APP_NAME} on port {APP_PORT}")
    # Start server with Server-Sent Events transport
    mcp.run(transport="sse")
