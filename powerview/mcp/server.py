"""
MCP Server implementation for PowerView.
"""

import asyncio
import logging
import json
import threading
import sys
import socket
import time
from typing import Dict, List, Optional, Any, Tuple, Union, Callable

from .src import tools, prompts, resources

try:
    from fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

class MCPServer:
    """
    Model Context Protocol server for PowerView.
    
    This class implements an MCP server that exposes PowerView's functionality
    to AI assistants using the Model Context Protocol.
    """
    
    def __init__(self, powerview, name="PowerView MCP", host="127.0.0.1", port=8080, path="/powerview"):
        """
        Initialize the MCP server.
        
        Args:
            powerview: PowerView instance to expose via MCP
            name: Name of the MCP server
            host: Host to bind the server to
            port: Port to bind the server to
            path: Path to bind the server to
        """
        if not MCP_AVAILABLE:
            raise ImportError("MCP dependencies not installed. Install with: pip install powerview[mcp]")
            
        self.powerview = powerview
        self.stack_trace = getattr(powerview.args, "stack_trace", False)
        self.name = name
        self.host = host
        self.port = port
        self.path = path if path.startswith('/') else '/' + path
        self.mcp = FastMCP(self.name)
        self.status = False
        self.server_thread = None
        tools.setup_tools(self.mcp, self.powerview)
        resources.setup_resources(self.mcp, self.powerview)
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
            logging.info(f"Starting MCP server on {self.host}:{self.port}")
            try:
                try:
                    self.mcp.run(
                        transport="http",
                        show_banner=False,
                        host=self.host,
                        port=self.port,
                        path=self.path,
                        log_level="error" if not self.stack_trace else "debug",
                        on_start=self._server_started
                    )
                except TypeError:
                    self.mcp.run(
                        transport="http",
                        show_banner=False,
                        host=self.host,
                        port=self.port,
                        path=self.path,
                        log_level="error" if not self.stack_trace else "debug"
                    )
            except Exception as e:
                self.set_status(False)
                logging.error(f"Error starting MCP server: {str(e)}")
                sys.exit(1)

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Probe the port to confirm readiness if on_start hook not supported
        start_time = time.time()
        timeout = 3.0
        while time.time() - start_time < timeout and not self.get_status():
            try:
                with socket.create_connection((self.host, int(self.port)), timeout=0.25):
                    self.set_status(True)
                    break
            except Exception:
                time.sleep(0.1)

        logging.debug(f"MCP server thread started, status: {self.get_status()}")

    def stop(self):
        """Stop the MCP server."""
        logging.info("Stopping MCP server...")
        try:
            # Best-effort stop if FastMCP exposes a stop/shutdown API
            if hasattr(self.mcp, 'stop') and callable(getattr(self.mcp, 'stop')):
                self.mcp.stop()
        except Exception as e:
            logging.debug(f"MCP stop hint failed: {e}")
        self.set_status(False)