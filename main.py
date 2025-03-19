# mcp/main.py
import os
import subprocess
from mcp.server.fastmcp import FastMCP
from starlette.exceptions import HTTPException
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MCP API key
MCP_API_KEY = os.getenv("MCP_API_KEY", 'test1234')

# Middleware function to check API key authentication
def middleware(request):
    # Verify the x-api-key header matches the environment variable
    if request.headers.get("x-api-key") != MCP_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# Server configuration settings
settings = {
    'debug': True,          # Enable debug mode
    'port': 8005,          # Port to run server on
    'log_level': 'DEBUG',  # Logging verbosity
    # 'middleware': middleware, # Authentication middleware
}

# Initialize FastMCP server instance
mcp = FastMCP(name="Terminal", **settings)

@mcp.tool()
async def shell_command(command: str) -> str:
    """Execute a shell command"""
    return subprocess.check_output(command, shell=True).decode()

if __name__ == "__main__":
    print("Starting MCP server...")
    # Start server with Server-Sent Events transport
    mcp.run(transport="sse")