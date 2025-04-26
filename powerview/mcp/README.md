# PowerView MCP Integration

This directory contains the implementation of the Model Context Protocol (MCP) server for PowerView, allowing AI assistants to interact with PowerView's functionality.

## What is MCP?

The Model Context Protocol (MCP) is an open standard that enables AI assistants to interact with external tools and services. It provides a standardized way for AI agents to discover and use capabilities provided by servers.

MCP defines three primary primitives:
- **Resources**: Contextual data managed by the application (Note: Currently, specific MCP resources are not explicitly defined in this server implementation).
- **Tools**: Functions that can be invoked by the AI.
- **Prompts**: Interactive templates that help the AI generate better responses.

## Usage

To start PowerView with MCP support, use the `--mcp` flag:

```bash
python powerview.py domain.local/username:password@dc01.domain.local --mcp
```

By default, the MCP server will listen on `127.0.0.1:8080`. You can customize this with the following flags:

```bash
python powerview.py domain.local/username:password@dc01.domain.local --mcp [--mcp-host 0.0.0.0] [--mcp-port 9000]
```

## Available Capabilities

### Tools

PowerView exposes the following tools via MCP (this list is generated from the code):

- `login_as`: Login as a different user.
- `get_domain_user`: Get information about domain users.
- `get_domain_computer`: Get information about domain computers.
- `get_domain_group`: Get information about domain groups.
- `get_domain_group_member`: Get members of a domain group.
- `get_domain_controller`: Get information about domain controllers.
- `get_domain_trust`: Get information about domain trusts.
- `get_domain`: Get domain information.
- `get_domain_object_acl`: Get the ACLs for domain objects.
- `get_domain_ou`: Get information about organizational units (OUs).
- `get_domain_gpo`: Get information about Group Policy Objects (GPOs).
- `get_domain_gpo_localgroup`: Get local group membership from GPOs.
- `get_domain_gpo_settings`: Parse and return GPO settings from SYSVOL.
- `get_domain_dns_zone`: Get information about DNS zones.
- `invoke_kerberoast`: Perform Kerberoasting against service accounts.
- `invoke_asreproast`: Perform AS-REP Roasting against accounts with Kerberos pre-authentication disabled.
- `get_domain_ca`: Get information about domain certificate authorities.
- `get_domain_ca_template`: Get information about certificate templates.
- `get_domain_gmsa`: Get information about Group Managed Service Accounts (gMSAs).
- `get_domain_object_owner`: Gets the owner of specified domain objects.
- `get_exchange_server`: Get information about Exchange servers.
- `get_netshare`: Enumerates shares on a specified computer.
- `set_domain_user_password`: Sets the password for a specified domain user.
- `add_domain_user`: Adds a new domain user.
- `remove_domain_user`: Removes a domain user.
- `add_domain_group_member`: Adds one or more members to a domain group.
- `remove_domain_group_member`: Removes one or more members from a domain group.
- `add_domain_object_acl`: Adds an Access Control Entry (ACE) to a domain object's ACL.
- `remove_domain_object_acl`: Removes an Access Control Entry (ACE) from a domain object's ACL.
- `set_domain_object_owner`: Sets the owner for a specified domain object.
- `set_domain_computer_password`: Sets the password for a specified domain computer account.
- `convert_sid_to_name`: Convert a SID to a name.
- `get_current_auth_context`: Get the current authenticated user context.
- `generate_findings_report`: Generate a custom security findings report.
- `find_localadminaccess`: Enumerate computers where the current user has local admin access.
- `smb_connect`: Establish an SMB connection to target system.
- `smb_shares`: List available SMB shares on a target system.
- `smb_ls`: List contents of a directory on a remote SMB share.
- `smb_get`: Download a file from an SMB share.
- `smb_put`: Upload a file to an SMB share.
- `smb_cat`: Read the content of a file from an SMB share.
- `smb_rm`: Remove a file from an SMB share.
- `smb_mkdir`: Create a directory on an SMB share.
- `smb_rmdir`: Remove a directory from an SMB share.

### Prompts

PowerView provides the following prompt templates (via `prompts.py`):

- `find_vulnerable_systems` - A prompt to help identify vulnerable systems.
- `ad_mapping_prompt` - A prompt to map the Active Directory environment.

## Dependencies

If you encounter errors when running mcp, thats probably because of dependencies error. To use the MCP integration, you need to install the required dependencies, which includes the MCP SDK. You can typically install these using the `[mcp]` extra:

```bash
pip install .[mcp]
```

## References

- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Awesome MCP Servers](https://github.com/punkpeye/awesome-mcp-servers)
- [Elasticsearch MCP Server](https://github.com/cr7258/elasticsearch-mcp-server) 