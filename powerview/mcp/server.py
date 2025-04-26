"""
MCP Server implementation for PowerView.
"""

import asyncio
import logging
import json
import threading
import sys
from typing import Dict, List, Optional, Any, Tuple, Union, Callable

from .src import tools, prompts

try:
    from mcp.server.fastmcp import FastMCP, Context
    import mcp.types as types
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

class MCPServer:
    """
    Model Context Protocol server for PowerView.
    
    This class implements an MCP server that exposes PowerView's functionality
    to AI assistants using the Model Context Protocol.
    """
    
    def __init__(self, powerview, name="PowerView MCP", host="127.0.0.1", port=8080):
        """
        Initialize the MCP server.
        
        Args:
            powerview: PowerView instance to expose via MCP
            name: Name of the MCP server
            host: Host to bind the server to
            port: Port to bind the server to
        """
        if not MCP_AVAILABLE:
            raise ImportError("MCP dependencies not installed. Install with: pip install .[mcp]")
            
        self.powerview = powerview
        self.name = name
        self.host = host
        self.port = port
        self.mcp = FastMCP(self.name)
        self.status = False
        self.server_thread = None
        # self._setup_resources() # Remove or comment out this line
        tools.setup_tools(self.mcp, self.powerview)
        prompts.setup_prompts(self.mcp)

    def set_status(self, status):
        self.status = status

    def get_status(self):
        return self.status

    async def _server_started(self):
        """Callback that runs when the server is actually ready to accept connections"""
        self.set_status(True)
        logging.info("MCP server is ready to accept connections")

    def start(self):
        """Start the MCP server."""
        if self.server_thread and self.server_thread.is_alive():
            logging.warning("MCP server is already running")
            return
        
        def run_server():
            import uvicorn
            
            logging.info(f"Starting MCP server on {self.host}:{self.port}")
            try:
                # Create an ASGI application from the MCP server
                app = self.mcp.sse_app()
                
                # Set status before starting server
                self.set_status(True)
                
                # Start the server with uvicorn
                uvicorn.run(
                    app=app,
                    host=self.host,
                    port=self.port,
                    log_level="error",
                    access_log=False
                )
            except Exception as e:
                self.set_status(False)
                logging.error(f"Error starting MCP server: {str(e)}")
                sys.exit(1)

        # Create and start the server thread
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        import time
        time.sleep(0.2)
        
        logging.debug(f"MCP server thread started, status: {self.get_status()}")

    def stop(self):
        """Stop the MCP server."""
        self.set_status(False)
        logging.info("Stopping MCP server...")
        
        # The MCP server will stop when the main thread exits since we use a daemon thread 