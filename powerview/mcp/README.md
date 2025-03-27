# PowerView MCP Integration

This directory contains the implementation of the Model Context Protocol (MCP) server for PowerView, allowing AI assistants to interact with PowerView's functionality.

## What is MCP?

The Model Context Protocol (MCP) is an open standard that enables AI assistants to interact with external tools and services. It provides a standardized way for AI agents to discover and use capabilities provided by servers.

MCP defines three primary primitives:
- **Resources**: Contextual data managed by the application
- **Tools**: Functions that can be invoked by the AI
- **Prompts**: Interactive templates that help the AI generate better responses

## Usage

To start PowerView with MCP support, use the `--mcp` flag:

```bash
python powerview.py domain.local/username:password@dc01.domain.local --mcp
```

By default, the MCP server will listen on `127.0.0.1:8080`. You can customize this with the following flags:

```bash
python powerview.py domain.local/username:password@dc01.domain.local --mcp --mcp-host 0.0.0.0 --mcp-port 9000 --mcp-name "My PowerView"
```

## Available Capabilities

### Resources

The following resources are available:

- `powerview://domain/{domain}` - Domain information
- `powerview://users/{identity}` - User information
- `powerview://computers/{identity}` - Computer information
- `powerview://groups/{identity}` - Group information

### Tools

PowerView exposes the following tools via MCP:

- `get_domain_user` - Get information about domain users
- `get_domain_computer` - Get information about domain computers
- `get_domain_group` - Get information about domain groups
- `get_domain_group_member` - Get members of a domain group
- `get_domain_controller` - Get information about domain controllers
- `find_local_admin_access` - Find local admin access on computers
- `get_domain_trust` - Get information about domain trusts
- `get_domain_policy` - Get domain policy information

### Prompts

PowerView provides the following prompt templates:

- `find_vulnerable_systems` - A prompt to help identify vulnerable systems
- `ad_mapping_prompt` - A prompt to map the Active Directory environment

## Example Client

An example client script is provided in `example_client.py` that demonstrates how to connect to the PowerView MCP server and use its capabilities.

To run the example client:

```bash
python example_client.py 127.0.0.1 8080
```

## Dependencies

To use the MCP integration, you need to install the MCP SDK:

```bash
pip install mcp
```

## References

- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Awesome MCP Servers](https://github.com/punkpeye/awesome-mcp-servers)
- [Elasticsearch MCP Server](https://github.com/cr7258/elasticsearch-mcp-server) 