"""
Model Context Protocol (MCP) integration for PowerView.

This module provides MCP server functionality for PowerView, allowing
AI assistants to interact with PowerView's capabilities.

Note: This is an optional component that requires additional dependencies.
Install with: pip install .[mcp]
"""

try:
    from .server import MCPServer
    __all__ = ['MCPServer']
except ImportError:
    # This allows the package to be imported even if MCP dependencies aren't installed
    import logging
    logging.warning("MCP dependencies not installed. To use MCP features, install with: pip install .[mcp]")
    
    # Create a stub class that raises an error when instantiated
    class MCPServer:
        def __init__(self, *args, **kwargs):
            raise ImportError("MCP dependencies not installed. Install with: pip install .[mcp]")
    
    __all__ = ['MCPServer'] 