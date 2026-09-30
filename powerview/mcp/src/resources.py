from powerview.utils.session import session_guard

import logging
import json

def setup_resources(mcp, powerview_instance):
	"""Register all PowerView resources with the MCP server."""

	@mcp.resource("powerview://connection_info")
	@session_guard(powerview_instance)
	def get_connection_info() -> str:
		"""Get current PowerView connection info (protocol, server, domain)."""
		try:
			info = {
				"identity": powerview_instance.conn.who_am_i(),
				"protocol": powerview_instance.conn.get_proto(),
				"server": powerview_instance.get_server_dns(),
				"domain": powerview_instance.conn.get_domain(),
			}
			return json.dumps({"data": info})
		except Exception as e:
			logging.error(f"Error in get_connection_info: {str(e)}")
			return json.dumps({"error": str(e)})
