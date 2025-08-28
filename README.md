<p align="center">
    <img style="width: 800px;" alt="Powerview.py" src="https://github.com/user-attachments/assets/11771cef-66dc-407c-aae3-7e1c879723c5" />
</p>
<hr />

<p align="center">

<img src="https://img.shields.io/badge/version-2025.1.6-blue" alt="version 2025.1.6"/>

<a href="https://x.com/aniqfakhrul">
    <img src="https://img.shields.io/twitter/follow/aniqfakhrul?style=social"
      alt="@aniqfakhrul on X"/></a>
<a href="https://x.com/h0j3n">
    <img src="https://img.shields.io/twitter/follow/h0j3n?style=social"
      alt="@h0j3n on X"/></a>
</p>
<hr />

[Installation](#installation) | [Basic Usage](#basic-usage) | [Obfuscation](#obfuscation) | [Modules](#module-available-so-far) | [Logging](#logging) | [User Defined Rules](#user-defined-rules) | [MCP](#mcp) | [Acknowledgements](#acknowledgements)

## Overview

PowerView.py is an alternative for the awesome original [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script. Most of the modules used in PowerView are available here ( some of the flags are changed ). Main goal is to achieve interactive session without having to repeatedly authenticate to ldap.

## Installation
https://github.com/aniqfakhrul/powerview.py/wiki/Installation-Guide

## Basic Usage
> [!NOTE]
> Note that some of the kerberos functions are still not functioning well just yet but it'll still do most of the works. Detailed usage can be found in [Wiki](https://github.com/aniqfakhrul/powerview.py/wiki) section

* Init connection
```
powerview range.net/lowpriv:Password123@192.168.86.192 [-k] [--use-ldap | --use-ldaps | --use-gc | --use-gc-ldaps | --use-adws]
```

* Maintain persistent connection
> [!TIP]
> Connection persistence is disabled by default. LDAP sessions timeout after inactivity. Use `--keepalive-interval` to send periodic queries maintaining session state.

* Start web interface
```
powerview range.net/lowpriv:Password123@192.168.86.192 --web [--web-host 0.0.0.0] [--web-port 3000] [--web-auth user:password1234]
```
![IMG_4602](https://github.com/user-attachments/assets/15bcd3e3-0693-4b0c-9c58-c8f36d899486)

* Init connection with specific authentication. Note that `--use-sign-and-seal` and `--use-channel-binding` is only available if you install `ldap3` library directly from this [branch](https://github.com/ThePirateWhoSmellsOfSunflowers/ldap3/tree/tls_cb_and_seal_for_ntlm) 
```
powerview range.net/lowpriv:Password123@192.168.86.192 [--use-channel-binding | --use-sign-and-seal | --use-simple-auth]
```
* Init with schannel. `--pfx` flag accept pfx formatted certificate file.
> [!NOTE]  
> powerview will try to load certificate without password on the first attempt. If it fails, it'll prompt for password. So, no password parameter needed
```
powerview 10.10.10.10 --pfx administrator.pfx
```
![intro](https://github.com/user-attachments/assets/286de18a-d0a4-4211-87c2-3736bb1e3005)

* Query for specific user
```
Get-DomainUser Administrator
Get-DomainUser -Identity Administrator
```

* Specify search attributes
```
Get-DomainUser -Properties samaccountname,description
```

* Filter results
```
Get-DomainUser -Where 'samaccountname [contains][in][eq] admins'
```

* Count results
```
Get-DomainUser -Count
```

* Output result to file
```
Get-DomainUser -OutFile ~/domain_user.txt
```

* Format output in a table.

```
Get-DomainUser -Properties samaccountname,memberof -TableView
Get-DomainUser -Properties samaccountname,memberof -TableView [csv,md,html,latex]
```

* Set module
```
Set-DomainObject -Identity "adminuser" -Set 'servicePrincipalname=http/web.ws.local'
Set-DomainObject -Identity "adminuser" -Append 'servicePrincipalname=http/web.ws.local'
Set-DomainObject -Identity "adminuser" -Clear 'servicePrincipalname'

# Reading from local file
Set-DomainObject -Identity "adminuser" -Set 'servicePrincipalname=@/path/to/local/file'
Set-DomainObject -Identity "adminuser" -Append 'servicePrincipalname=@/path/to/local/file'
```

* Relay mode
```
powerview 10.10.10.10 --relay [--relay-host] [--relay-port] [--use-ldap | --use-ldaps]
```

![relay](https://github.com/user-attachments/assets/4f219920-0cb0-4e81-ab6f-b6c94381a95f)


> [!NOTE]  
> This demonstration shows coerced authentication was made using `printerbug.py`. You may use other methods that coerce HTTP authentication.

### Obfuscation

PowerView can obfuscate LDAP queries and related parameters to vary observable patterns while preserving query intent.

* Enable via CLI
```
powerview range.net/lowpriv:Password123@192.168.86.192 --obfuscate
```

* Enable via Web
> [!TIP]
> Toggle `Obfuscate` in Settings. This applies to subsequent queries for the active session.

**What gets obfuscated**
- Filter: transforms attribute names, operators and values before sending
- DN: mutates the search base distinguishedName
- Attributes: mutates the requested attribute list

**Techniques used**
- OID attribute encoding with spacing/zero-variation (prefix omitted for compatibility)
- Random casing of attributes/values
- Numeric/SID zero-prepend on values
- Hex-encoding of eligible values
- Context-aware spacing in filters and DNs
- Equality to approximation operator substitution
- Wildcard expansion
- ANR attribute randomization
- DN hex escaping + random casing
- Attribute list OID aliasing + random casing

> [!NOTE]
> Results are functionally equivalent in most cases, but approximation/wildcard expansions can broaden matches. Performance may vary.

> [!warning]
> Excessive obfuscation may be rejected by strict servers or intermediary tooling. Use only when needed.

* ldapx: Flexible LDAP proxy used for inspiration and reference on filter/DN/attribute transformations — https://github.com/Macmod/ldapx
* Research: MaLDAPtive: Obfuscation and De-Obfuscation (DEF CON 32 talk) — https://www.youtube.com/watch?v=mKRS5Iyy7Qo
* Authors: Sabajete Elezaj — https://x.com/sabi_elezi, Daniel Bohannon — https://x.com/danielhbohannon

## Module available (so far?)

```cs
PV >
Add-ADComputer                 Find-ForeignUser               Get-DomainTrustKey             Invoke-PrinterBug              Restore-DomainObject 
Add-ADUser                     Find-LocalAdminAccess          Get-DomainUser                 Login-As                       Set-ADObject 
Add-CATemplate                 Get-ADObject                   Get-DomainWDS                  Logoff-Session                 Set-ADObjectDN 
Add-CATemplateAcl              Get-CA                         Get-ExchangeDatabase           Reboot-Computer                Set-CATemplate 
Add-DMSA                       Get-CATemplate                 Get-ExchangeMailbox            Remove-ADComputer              Set-DomainCATemplate 
Add-DomainCATemplate           Get-DMSA                       Get-ExchangeServer             Remove-ADObject                Set-DomainComputerPassword 
Add-DomainCATemplateAcl        Get-Domain                     Get-GMSA                       Remove-ADUser                  Set-DomainDNSRecord 
Add-DomainComputer             Get-DomainCA                   Get-GPOLocalGroup              Remove-CATemplate              Set-DomainObject 
Add-DomainDMSA                 Get-DomainCATemplate           Get-GPOSettings                Remove-DMSA                    Set-DomainObjectDN 
Add-DomainDNSRecord            Get-DomainComputer             Get-LocalUser                  Remove-DomainCATemplate        Set-DomainObjectOwner 
Add-DomainGMSA                 Get-DomainController           Get-NamedPipes                 Remove-DomainComputer          Set-DomainRBCD 
Add-DomainGPO                  Get-DomainDMSA                 Get-NetComputerInfo            Remove-DomainDMSA              Set-DomainUserPassword 
Add-DomainGroup                Get-DomainDNSRecord            Get-NetLoggedOn                Remove-DomainDNSRecord         Set-NetService 
Add-DomainGroupMember          Get-DomainDNSZone              Get-NetProcess                 Remove-DomainGMSA              Set-ObjectOwner 
Add-DomainOU                   Get-DomainForeignGroupMember   Get-NetService                 Remove-DomainGroupMember       Set-RBCD 
Add-DomainObjectAcl            Get-DomainForeignUser          Get-NetSession                 Remove-DomainOU                Shutdown-Computer 
Add-DomainUser                 Get-DomainGMSA                 Get-NetShare                   Remove-DomainObject            Start-NetService 
Add-GMSA                       Get-DomainGPO                  Get-NetTerminalSession         Remove-DomainObjectAcl         Stop-Computer 
Add-GPLink                     Get-DomainGPOLocalGroup        Get-ObjectAcl                  Remove-DomainUser              Stop-NetProcess 
Add-GPO                        Get-DomainGPOSettings          Get-ObjectOwner                Remove-GMSA                    Stop-NetService 
Add-GroupMember                Get-DomainGroup                Get-RBCD                       Remove-GPLink                  Unlock-ADAccount 
Add-NetService                 Get-DomainGroupMember          Get-RegLoggedOn                Remove-GroupMember             clear 
Add-OU                         Get-DomainOU                   Get-SCCM                       Remove-NetService              exit 
Add-ObjectAcl                  Get-DomainObject               Get-TrustKey                   Remove-NetSession              get_pool_stats 
Clear-Cache                    Get-DomainObjectAcl            Get-WDS                        Remove-NetTerminalSession      history 
ConvertFrom-SID                Get-DomainObjectOwner          Invoke-ASREPRoast              Remove-OU                      taskkill 
ConvertFrom-UACValue           Get-DomainRBCD                 Invoke-DFSCoerce               Remove-ObjectAcl               tasklist 
Disable-DomainDNSRecord        Get-DomainSCCM                 Invoke-Kerberoast              Restart-Computer               
Find-ForeignGroup              Get-DomainTrust                Invoke-MessageBox              Restore-ADObject               
```

### Domain/LDAP Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainUser||Query for all users or specific user objects in AD|
|Get-DomainComputer||Query for all computers or specific computer objects in AD|
|Get-DomainGroup||Query for all groups or specific group objects in AD|
|Get-DomainGroupMember||Query the members for specific domain group |
|Get-DomainOU||Query for all OUs or specific OU objects in AD|
|Get-Domain||Query for domain information|
|Get-DomainController||Query for available domain controllers|
|Get-DomainDNSRecord||Query for available records. It will recurse all DNS zones if doesn't specify -ZoneName|
|Get-DomainDNSZone||Query for available DNS zones in the domain|
|Get-DomainObject|Get-ADObject|Query for all or specified domain objects in AD|
|Get-DomainObjectAcl|Get-ObjectAcl|Query ACLs for specified AD object|
|Get-DomainSCCM|Get-SCCM|Query for SCCM|
|Get-DomainRBCD|Get-RBCD|Finds accounts that are configured for resource-based constrained delegation|
|Get-DomainObjectOwner|Get-ObjectOwner|Query owner of the AD object|
|Get-DomainGMSA|Get-GMSA|Query for Group Managed Service Accounts (gMSA) and retrieve their password blobs|
|Get-DomainDMSA|Get-GDSA|Query for Delegated Managed Service Accounts (dMSA)|
|Remove-DomainGMSA|Remove-GMSA|Delete an existing Group Managed Service Account (GMSA) from the domain|
|Remove-DomainDMSA|Remove-DMSA|Delete an existing Delegated Managed Service Account (dMSA) from the domain|
|Remove-DomainDNSRecord||Remove Domain DNS Record|
|Remove-DomainComputer|Remove-ADComputer|Remove Domain Computer|
|Remove-DomainGroupMember|Remove-GroupMember|Remove member of a specific Domain Group|
|Remove-DomainOU|Remove-OU|Remove OUs or specific OU objects in AD|
|Remove-DomainObjectAcl|Remove-ObjectAcl|Remove ACLs for specified AD object|
|Remove-DomainObject|Remove-ADObject|Remove specified Domain Object|
|Remove-DomainUser|Remove-ADUser|Remove specified Domain User in AD|
|Set-DomainDNSRecord||Set Domain DNS Record|
|Set-DomainUserPassword||Set password for specified Domain User|
|Set-DomainComputerPassword||Set password for specified Domain Computer|
|Set-DomainObject|Set-ADObject|Set for specified domain objects in AD|
|Set-DomainObjectDN|Set-ADObjectDN| Modify object's distinguishedName attribute as well as changing OU|
|Set-DomainObjectOwner|Set-ObjectOwner|Set owner of the AD object|
|Add-DomainDNSRecord||Add Domain DNS Record|
|Disable-DomainDNSRecord||Disabling DNS Record by pointing to invalid address|
|Add-DomainGMSA|Add-GMSA|Create a new Group Managed Service Account (gMSA) in the domain|
|Add-DomainDMSA|Add-GMSA|Create a new Delegated Managed Service Account (dMSA) in the domain|
|Add-DomainUser|Add-ADUser|Add new Domain User in AD|
|Add-DomainComputer|Add-ADComputer|Add new Domain Computer in AD|
|Add-DomainGroupMember|Add-GroupMember|Add new member in specified Domain Group in AD|
|Add-DomainOU|Add-OU|Add new OU object in AD|
|Add-DomainGPO|Add-GPO|Add new GPO object in AD|
|Add-DomainObjectAcl|Add-ObjectAcl|Supported rights so far are All, DCsync, RBCD, ShadowCred, WriteMembers|
|Clear-Cache||Clear cache|

### GPO Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainGPO|| Query for domain group policy objects |
|Get-DomainGPOLocalGroup|Get-GPOLocalGroup|Query all GPOs in a domain that modify local group memberships through `Restricted Groups` or `Group Policy preferences`|
|Add-GPLink||Create new GPO link to an OU|
|Remove-GPLink||Remove GPO link from an OU|

### Computer Enumeration Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-NetSession||[MS-SRVS] Query session information for the local or a remote computer|
|Get-NetShare||Query open shares on the local or a remote computer|
|Get-NetLoggedOn||[MS-WKST] Query logged on users on the local or a remote computer|
|Get-NetService||[MS-SCMR] Query running services on the local or a remote computer|
|Stop-NetService||[MS-SCMR] Stop a specific service on the local or a remote computer|
|Get-NetProcess|tasklist|[MS-TSTS] Query running processes on the local or a remote computer|
|Stop-NetProcess|taskkill|[MS-TSTS] Terminate a specific process on the local or a remote computer|
|Get-NetTerminalSession||[MS-TSTS] Query active terminal sessions on the local or a remote computer|
|Remove-NetTerminalSession||[MS-TSTS] Terminate a specific terminal session on the local or a remote computer|
|Stop-Computer|Shutdown-Computer|[MS-TSTS] Shutdown a remote computer|
|Restart-Computer|Reboot-Computer|[MS-TSTS] Restart a remote computer|

### ADCS Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainCATemplate|Get-CATemplate|Query for available CA templates. Supports filtering for vulnerable template|
|Get-DomainCA|Get-CA|Query for Certificate Authority(CA)|
|Remove-DomainCATemplate|Remove-CATemplate|Remove specified Domain CA Template|
|Set-DomainCATemplate|Set-CATemplate|Modify domain object's attributes of a CA Template|
|Add-DomainCATemplate|Add-CATemplate|Add new Domain CA Template|
|Add-DomainCATemplateAcl|Add-CATemplateAcl|Add ACL to a certificate template. Supported rights so far are All, Enroll, Write|

### Exchange Functions

| Module | Alias | Description |
| ------ | ----- | ----------- |
|Get-ExchangeServer|Get-Exchange|Retrieve list of available exchange servers in the domain|

### Domain Trust Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainTrust||Query all Domain Trusts|
|Get-DomainForeignUser|Find-ForeignUser|Query users who are in group outside of the user's domain|
|Get-DomainForeignGroupMember|Find-ForeignGroup|Query groups with users outside of group's domain and look for foreign member|

### Misc Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|ConvertFrom-SID||Convert a given security identifier (SID) to user/group name|
|ConvertFrom-UACValue||Converts a UAC int value to human readable form|
|Get-NamedPipes||List out Named Pipes for a specific computer|
|Invoke-DFSCoerce||Coerces machine account authentication via MS-DFSNM NetrDfsRemoveStdRoot()|
|Invoke-Kerberoast||Requests kerberos ticket for a specified service principal name (SPN)|
|Invoke-PrinterBug||Triggers the MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx function to force a server to authenticate to a specified machine|
|Unlock-ADAccount||Unlock domain accounts by modifying lockoutTime attribute|
|Find-LocalAdminAccess||Finds computer on the local domain where the current has a Local Administrator access|

### Logging

We will never miss logging to keep track of the actions done. By default, powerview creates a `.powerview` folder in current user home directory _(~)_. Each log file is generated based on current date.
Example path: `/root/.powerview/logs/bionic.local/2024-02-13.log`

### Vulnerability Detection

PowerView.py includes an integrated vulnerability detection system that automatically identifies common Active Directory security issues. When querying objects, vulnerabilities will be displayed in the output:

```
vulnerabilities: [VULN-026] Domain with high machine account quota (allows users to add computer accounts) (MEDIUM)
                 [VULN-029] Domain with weak minimum password length policy (less than 8 characters) (HIGH)
```

#### User Defined Rules

You can define custom vulnerability detection rules by modifying the `vulns.json` file located in the PowerView storage directory (`~/.powerview/vulns.json`).

Each vulnerability rule has the following structure:

```json
"rule_name": {
    "description": "Human-readable description of the vulnerability",
    "rules": [
        {
            "attribute": "attributeName",
            "condition": "condition_type",
            "value": "value_to_check"
        },
        {
            "attribute": "anotherAttribute",
            "condition": "another_condition",
            "value": "another_value"
        }
    ],
    "exclusions": [
        {
            "attribute": "attributeName",
            "condition": "condition_type",
            "value": "value_to_exclude"
        }
    ],
    "severity": "low|medium|high|critical",
    "id": "VULN-XXX",
    "rule_operator": "AND|OR",
    "exclusion_operator": "AND|OR",
    "details": "Optional detailed explanation of the vulnerability and remediation steps"
}
```

**Rule Components:**

- **rules**: List of conditions that must be met for the vulnerability to be detected
- **exclusions**: List of conditions that, if met, will exclude an object from detection even if it matches the rules
- **rule_operator**: How to combine multiple rules (default: "OR")
  - "AND": All rules must match
  - "OR": Any rule can match
- **exclusion_operator**: How to combine multiple exclusions (default: "OR")
  - "OR": Any exclusion can match to exclude the object
  - "AND": All exclusions must match to exclude the object
- **negate**: Optional boolean (True/False) that can be added to any rule to invert its result

**Supported Conditions:**

| Condition | Description |
| --------- | ----------- |
| `exists` | Attribute exists |
| `not_exists` | Attribute does not exist |
| `equals` | Exact match (case-insensitive) |
| `not_equals` | Not an exact match |
| `contains` | Substring match (case-insensitive) |
| `not_contains` | No substring match |
| `startswith` | Starts with string (case-insensitive) |
| `endswith` | Ends with string (case-insensitive) |
| `older_than` | Date is older than specified number of days |
| `newer_than` | Date is newer than specified number of days |
| `greater_than` | Numeric value is greater than specified |
| `less_than` | Numeric value is less than specified |
| `greater_than_or_equal` | Numeric value is greater than or equal to specified |
| `less_than_or_equal` | Numeric value is less than or equal to specified |
| `has_flag` | Bit flag is set in a numeric value |
| `missing_flag` | Bit flag is not set in a numeric value |
| `any_flag_set` | Any of the specified flags are set |
| `all_flags_set` | All of the specified flags are set |

**Multiple Values:**

You can specify multiple values for a condition using:
1. Pipe-separated string: `"value": "value1|value2|value3"`
2. List format: `"value": ["value1", "value2", "value3"]`

**Example Rule:**

```json
"weak_password_policy": {
    "description": "Domain with weak minimum password length policy (less than 8 characters)",
    "rules": [
        {
            "attribute": "objectClass",
            "condition": "contains",
            "value": "domainDNS"
        },
        {
            "attribute": "minPwdLength",
            "condition": "less_than",
            "value": 8
        }
    ],
    "exclusions": [],
    "severity": "high",
    "id": "VULN-029",
    "rule_operator": "AND"
}
```

### MCP

> [!note]
> This is not bundled in the base project installation. You may run `pip3 install .[mcp] or pip3 install powerview[mcp]` to include MCP functionalities.

This enables the Model Context Protocol server, allowing AI agents to interact with PowerView functionality through a standardized interface via Streamable HTTP transport. See the [MCP documentation](powerview/mcp/README.md) for more details.

* Start MCP server
```bash
powerview domain.local/lowpriv:Password1234@10.10.10.10 --mcp [--mcp-host 0.0.0.0] [--mcp-port 8888] [--mcp-path powerview]
```

The MCP server exposes most of PowerView's functionality through a standardized tool interface. This includes the ability to:
- Query and enumerate Active Directory objects (users, computers, groups, OUs)
- Retrieve information about domain trusts, GPOs, and group memberships
- Search for security vulnerabilities and misconfigurations
- ...

#### Claude Desktop
Claude Desktop does not support yet support HTTP based transport [Github](https://github.com/orgs/modelcontextprotocol/discussions/16). You may want to use [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy).

* Install `mcp-proxy`
```bash
# Option 1: With uv (recommended)
uv tool install mcp-proxy

# Option 2: With pipx (alternative)
pipx install mcp-proxy
``` 

* Modify `%APPDATA%\Claude\claude_desktop_config.json`
```json
{
  "mcpServers": {
    "Powerview": {
        "command": "mcp-proxy",
        "args": ["http://10.10.10.10:5000/powerview"]
    }
  }
}
```

#### Cursor
You can modify this in cursor settings under MCP options button.

>[!tip]
>Enable YOLO mode to enable autonomous mode so you don't have to click on "Run Tool" button each time. Read more [here](https://docs.cursor.com/chat/agent#yolo-mode)

```json
{
  "mcpServers": {
    "Powerview": {
      "url": "http://127.0.0.1:5000/powerview"
    }
  }
}
```

> [!warning]
> When using MCP with public AI models (like Claude, GPT, etc.), your Active Directory data may be transmitted to and logged by these services according to their data handling policies. Be mindful of sensitive information exposure when using these tools. We are not responsible for any data leakage or security implications resulting from connecting PowerView to third-party AI services. Self-hosted FTW!

### Credits
* https://github.com/SecureAuthCorp/impacket
* https://github.com/CravateRouge/bloodyAD
* https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
* https://github.com/ThePorgs/impacket/
* https://github.com/the-useless-one/pywerview
* https://github.com/dirkjanm/ldapdomaindump
* https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gplink
* https://github.com/ThePirateWhoSmellsOfSunflowers/ldap3/tree/tls_cb_and_seal_for_ntlm
* https://github.com/ly4k/Certipy
* https://github.com/MaLDAPtive/Invoke-Maldaptive
* https://github.com/xforcered/SoaPy
