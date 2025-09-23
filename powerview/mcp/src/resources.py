import logging

def setup_resources(mcp, powerview_instance):
	"""Register all PowerView resources with the MCP server."""

	@mcp.resource("user://current_auth_context")
	async def get_current_auth_context() -> str:
		"""Get the current authenticated user context for the PowerView session."""
		try:
			identity = powerview_instance.conn.who_am_i()
			username = identity.split("\\")[-1] if "\\" in identity else identity
			return {"data": {"identity": username}}
		except AttributeError:
			logging.error("Error in get_current_auth_context: powerview_instance or connection object not available.")
			return {"error": "Internal server error: Could not access connection details."}
		except Exception as e:
			logging.error(f"Error in get_current_auth_context: {str(e)}")
			return {"error": str(e)}