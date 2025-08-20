# Powerview Web API

This document describes all HTTP APIs supported by powerview.

Most endpoints accept and return JSON unless otherwise specified. When Basic Auth is configured at launch, all routes require it.

## Table of Contents

- [Health](#health)
- [Server and Schema Info](#server-and-schema-info)
- [Settings](#settings)
- [Connection and Domain Info](#connection-and-domain-info)
- [Generic Operation Wrappers](#generic-operation-wrappers)
- [Command Execution](#command-execution)
- [Constants](#constants)
- [Cache](#cache)
- [Logs and History](#logs-and-history)
- [LDAP Session Control](#ldap-session-control)
- [SMB Connection and Sessions](#smb-connection-and-sessions)
- [SMB Shares and Files](#smb-shares-and-files)
- [SMB ACL Management](#smb-acl-management)
- [SMB Search](#smb-search)
- [Impersonation](#impersonation)
- [Computer Control](#computer-control)

---

## Health

GET `/health`

- Description: Liveness check.
- Response 200: `{ "status": "ok" }`

---

## Server and Schema Info

GET `/api/server/info`

- Description: Returns server information from the active connection.
- Response 200: JSON object returned by `conn.get_server_info()`.

GET `/api/server/schema`

- Description: Returns schema information from the active connection.
- Response 200: JSON object returned by `conn.get_schema_info()`.

---

## Settings

GET `/api/settings`

- Description: Returns the current Powerview settings/arguments.
- Response 200: `vars(self.powerview.args)`

POST `/api/set/settings`

- Description: Updates key runtime settings and reinitializes LDAP extended ops.
- Body JSON (optional):
  - `obfuscate` (bool)
  - `no_cache` (bool)
  - `no_vuln_check` (bool)
- Response 200: `{ "status": "OK" }`
- Response 400: `{ "error": "..." }`

---

## Connection and Domain Info

GET `/api/connectioninfo`

- Description: Returns connection and user context info.
- Response 200 JSON fields: `domain`, `username`, `is_admin`, `status` (OK|KO), `protocol`, `ldap_address`, `nameserver`.

GET `/api/get/domaininfo`

- Description: Returns basic domain info.
- Response 200: `{ "domain", "root_dn", "dc_dnshostname", "flatName" }`

---

## Generic Operation Wrappers

These wrappers invoke `PowerView` methods dynamically.

- GET/POST `/api/get/<method>` → calls `powerview.get_<method>(**params)`
- POST `/api/set/<method>` → calls `powerview.set_<method>(**params)`
- POST `/api/add/<method>` → calls `powerview.add_<method>(**params)`
- POST `/api/remove/<method>` → calls `powerview.remove_<method>(**params)`
- POST `/api/invoke/<method>` → calls `powerview.invoke_<method>(**params)`
- POST `/api/start/<method>` → calls `powerview.start_<method>(**params)`
- POST `/api/stop/<method>` → calls `powerview.stop_<method>(**params)`
- POST `/api/convertfrom/<method>` → calls `powerview.convertfrom_<method>(**params)`
- POST `/api/convertto/<method>` → calls `powerview.convertto_<method>(**params)`

> [!note]
> For GET routes, parameters may be passed via query string; for POST, via JSON body.
> If the JSON includes an `args` object, it is converted to an `argparse.Namespace` and passed as `args`.
> Response: JSON serialization of the return value; `{ "error": "..." }` with 4xx on errors.

---

## Command Execution

POST `/api/execute`

- Description: Parses a PowerView CLI command string and executes it.
- Body JSON: `{ "command": "<pv command>" }`
- Response 200: `{ "result": <serialized>, "pv_args": { ...parsed args... } }`
- Response 400/500: `{ "error": "..." }`

---

## Constants

GET `/api/constants?get=uac`

- Description: Returns constant maps.
- Query (optional):
  - `get=uac` → returns `UAC` dictionary.
- Response 200: JSON map or `{}` if unsupported key.

---

## Cache

GET `/api/clear-cache`

- Description: Clears internal caches.
- Response: `200 { "status": "OK" }` or `400 { "status": "KO" }`

---

## Logs and History

GET `/api/logs`

- Description: Paged server log reader.
- Query (optional):
  - `page` (int, default 1)
  - `limit` (int, default 10, max 100)
- Response 200: `{ logs: [ { timestamp, user, log_type, debug_message } ], total, page, limit }`

GET `/api/history`

- Description: Returns last 50 CLI history entries.
- Response 200: `{ "result": ["..."] }`

---

## LDAP Session Control

GET `/api/ldap/rebind`

- Description: Rebind/reset LDAP connection.
- Response: `200 { "status": "OK" }` or `400 { "status": "KO" }`

GET `/api/ldap/close`

- Description: Close LDAP connection.
- Response: `200 { "status": "OK" }` or `400 { "status": "KO" }`

---

## SMB Connection and Sessions

POST `/api/smb/connect`

- Body JSON:
  - required: `computer`
  - optional: `username`, `password`, `domain`, `lmhash`, `nthash`, `aesKey`
> [!note]
> `username` may be `DOMAIN\\user` or `DOMAIN/user`. When using Kerberos, the host must be resolvable to FQDN.
- Response 200: `{ status: "connected", host }`

POST `/api/smb/reconnect`

- Body JSON:
  - required: `computer`
- Description: Reconnect using stored credentials if available.
- Response 200: `{ status: "reconnected", host, used_stored_creds: bool }`

POST `/api/smb/disconnect`

- Body JSON:
  - required: `computer`
- Response 200: `{ status: "disconnected" }`

GET `/api/smb/sessions`

- Description: Lists tracked SMB session stats.
- Response 200: `{ sessions: { <host>: { connected, last_used, use_count, age, last_check } } }`

---

## SMB Shares and Files

POST `/api/smb/shares`

- Body JSON:
  - required: `computer`
- Response 200: `[{ attributes: { Name, Remark, Address } }, ...]`

POST `/api/smb/add-share`

- Body JSON:
  - required: `computer`, `share_name`, `share_path`
- Response 200: `{ status: "success", message }`

POST `/api/smb/delete-share`

- Body JSON:
  - required: `computer`, `share`
- Response 200: `{ status: "success", message }`

POST `/api/smb/ls`

- Body JSON:
  - required: `computer`, `share`
  - optional: `path` (default "")
- Response 200: `[{ name, size, is_directory, created, modified, accessed }]`

POST `/api/smb/mv`

- Body JSON:
  - required: `computer`, `share`, `source`, `destination`
- Response 200: `{ message: "File moved successfully" }`

POST `/api/smb/get`

- Body JSON:
  - required: `computer`, `share`, `path`
- Response 200: Binary content with `Content-Disposition`.

POST `/api/smb/put`

- Content-Type: `multipart/form-data`
- Fields:
  - required: `file`, `computer`, `share`
  - optional: `path` (destination directory within share; default root)
- Response 200: `{ message: "File uploaded successfully" }`

POST `/api/smb/cat`

- Body JSON:
  - required: `computer`, `share`, `path`
- Response 200: Raw file content.

POST `/api/smb/rm`

- Body JSON:
  - required: `computer`, `share`, `path`
- Response 200: `{ message: "File deleted successfully" }`

POST `/api/smb/mkdir`

- Body JSON:
  - required: `computer`, `share`, `path`
- Response 200: `{ message: "Directory created successfully" }`

POST `/api/smb/rmdir`

- Body JSON:
  - required: `computer`, `share`, `path`
- Response 200: `{ message: "Directory deleted successfully" }`

POST `/api/smb/properties`

- Body JSON:
  - required: `computer`, `share`
  - optional: `path` (when omitted, returns share info)
- Response 200: Share info when `path` is empty, else file info. Owner and group are SID-resolved; DACL entries include trustee names where possible.

---

## SMB ACL Management

POST `/api/smb/set-security`

- Body JSON:
  - required: `computer`, `share`, `path`, `username`
  - optional: `mask` (default `fullcontrol`), `ace_type` (default `allow`)
- `mask`: one of `fullcontrol|modify|readandexecute|readandwrite|read|write`
- `ace_type`: `allow` or `deny`
- Response 200: `{ status: "success", message }`

POST `/api/smb/remove-security`

- Body JSON:
  - required: `computer`, `share`, `path`, `username`
  - optional: `mask`, `ace_type`
- Response 200/404/500 with `{ message|error }`

POST `/api/smb/set-share-security`

- Body JSON:
  - required: `computer`, `share`, `username`
  - optional: `mask` (default `fullcontrol`), `ace_type` (default `allow`)
- Response 200: `{ status: "success", message }`

POST `/api/smb/remove-share-security`

- Body JSON:
  - required: `computer`, `share`, `username`
  - optional: `mask`, `ace_type`
- Response 200/404/500 with `{ message|error }`

---

## SMB Search

POST `/api/smb/search`

- Body JSON:
  - required: `computer`, `share`
  - optional: `query`, `depth` (default 3), `start_path` (default ""), `use_regex` (default false), `content_search` (default false), `case_sensitive` (default false), `cred_hunt` (default false), `item_type` (`all|files|directories`, default `all`), `max_file_size` (default 5MB), `file_extensions` (when `content_search`)
- Response 200 JSON: `{ items, total, search_info: { ... } }`

GET `/api/smb/search-stream`

- Description: Server-Sent Events progressive search. Same semantics as `/api/smb/search` but via query string.
- Query:
  - required: `computer`, `share`
  - optional: same as POST `/api/smb/search`
> [!note]
> `query` is required unless `cred_hunt=true`.
- Headers: `Content-Type: text/event-stream`
- Events:
  - `data: { "type": "found", "item": { ... } }`
  - `data: { "type": "done", "total": N }`

---

## Impersonation

POST `/api/login_as`

- Body JSON:
  - required: `username`
  - optional: `password`, `domain`, `lmhash`, `nthash`, `auth_aes_key`
- Response 200 on success: `{ status: "success", message, connection_info }`
- Response 401 on failure: `{ status: "failure", error }`

---

## Computer Control

POST `/api/computer/restart`

- Body JSON:
  - required: `computer`
  - optional: `username`, `password`, `domain`, `lmhash`, `nthash`
  - constraint: if `username` is provided, one of `password|lmhash|nthash` is required
> [!note]
> FQDN is required when using Kerberos. Returns success if the reboot signal is sent; does not await completion.
- Response 200: `{ status: "OK", message }`

POST `/api/computer/shutdown`

- Body JSON:
  - required: `computer`
  - optional: `username`, `password`, `domain`, `lmhash`, `nthash`
  - constraint: if `username` is provided, one of `password|lmhash|nthash` is required
> [!note]
> Sends shutdown signal; does not await power-off completion.
- Response 200: `{ status: "OK", message }`

POST `/api/computer/tasklist`

- Body JSON:
  - required: `computer`
  - optional: `username`, `password`, `domain`, `lmhash`, `nthash`, `pid`, `name`
  - constraint: if `username` is provided, one of `password|lmhash|nthash` is required
> [!note]
> Filters by `pid` or case-insensitive substring match on `name` when provided.
- Response 200: `[{ attributes: { ImageName, PID, SessionID, SessionName, State, SessionUser, SID, MemUsage } }, ... ]`

---

## Error Handling

- On errors, endpoints return an error JSON: `{ "error": "<message>" }` with an appropriate 4xx/5xx status.
- Some endpoints return `status: "KO"` on operational failures with 400.


