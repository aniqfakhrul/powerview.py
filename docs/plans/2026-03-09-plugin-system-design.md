# Plugin System Design

## Overview

A decorator-based plugin system that lets users add new commands and hook before/after existing commands. Plugins are single `.py` files discovered from three paths. Plugin functions receive full access to the PowerView instance.

## Plugin Discovery Paths (scanned in order)

| Path | Purpose | Available after `uv tool install`? |
|------|---------|-------------------------------------|
| `powerview/plugins/builtin/` | Shipped with the package | Yes |
| `~/.powerview/plugins/` | User-managed plugins | Yes |
| `./plugins/` (CWD) | Project-local / dev use | No (only when running from source) |

User plugins load after built-in. Files starting with `_` are skipped. Alphabetical load order within each path.

## File Layout

```
powerview/
├── plugins/
│   ├── __init__.py        # Exports: @command, @before, @after
│   ├── registry.py        # PluginRegistry class
│   ├── loader.py          # Discovery & loading
│   └── builtin/           # Ships with package
│       └── example_plugin.py

~/.powerview/plugins/      # User plugins
./plugins/                 # Project-local (dev)
```

## Decorators

### `@command(name, args=None, description=None)`

Registers a new verb-noun command. Function signature: `(pv, args=None, **kwargs)`.

```python
@command("Get-CustomThing", args=["-Identity", "-Properties"])
def get_customthing(pv, args=None, identity=None, properties=[]):
    return pv.get_domainobject(identity=identity, properties=properties)
```

### `@before(command_name, priority=50)`

Runs before an existing command. Can modify args. Lower priority runs first.

```python
@before("Get-DomainUser", priority=10)
def filter_disabled(pv, args):
    if not args.ldapfilter:
        args.ldapfilter = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    return args
```

### `@after(command_name, priority=50)`

Runs after an existing command. Can modify results. Lower priority runs first.

```python
@after("Get-DomainUser", priority=20)
def enrich_results(pv, args, results):
    for entry in results:
        entry["CustomField"] = "enriched"
    return results
```

### Optional `setup(pv)`

Called after all decorators are processed. For imperative init, conditional registration, etc.

## PluginRegistry

Central store for commands and hooks:

- `commands` — dict keyed by verb-noun name, value has `func`, `args`, `description`
- `before_hooks` — dict keyed by command name, value is list of `(priority, func)` sorted by priority
- `after_hooks` — same structure as before_hooks

## Loader

`load_plugins(registry, pv)` scans all plugin paths:

1. For each `.py` file (excluding `_`-prefixed), dynamically import via `importlib.util`
2. Scan module for functions with `_plugin_command`, `_plugin_before`, `_plugin_after` attributes
3. Register each into the registry
4. Call `setup(pv)` if it exists
5. Log errors for bad plugins without crashing

## Integration Points

### `powerview.py` — `execute()` method

Modified to run before/after hooks around command dispatch:

1. Run before hooks (may modify args)
2. Check plugin commands first, then core methods via `getattr`
3. Run after hooks (may modify results)

### `__init__.py` — CLI REPL

At startup after PowerView init:

1. Create `PluginRegistry`, call `load_plugins(registry, pv)`
2. Attach registry to `pv.plugin_registry`
3. Inject plugin commands into argparse subparsers
4. Inject plugin commands into completer `COMMANDS` dict
5. Add elif fallback at bottom of dispatch chain for plugin commands

### `web/api/server.py` — No changes

`POST /api/execute` already routes through `PowerView.execute()`, so plugin commands and hooks work automatically.

### `parsers.py`, `completer.py` — No file changes

Both are mutated at runtime by the CLI startup code.

## Changes to Existing Files

| File | Change |
|------|--------|
| `powerview/powerview.py` | Add `plugin_registry` attribute, modify `execute()` for hooks |
| `powerview/__init__.py` | Load plugins at startup, inject into parser/completer, add dispatch fallback |
| `pyproject.toml` | Ensure `powerview/plugins/builtin/` is included in package |

## Example Plugin

```python
# ~/.powerview/plugins/custom_enum.py
from powerview.plugins import command, before, after

@command("Get-DomainUserEmail", args=["-Identity", "-SearchBase"],
         description="Get domain users with their email addresses")
def get_domainuseremail(pv, args=None, identity=None, searchbase=None):
    results = pv.get_domainuser(
        identity=identity or "*",
        properties=["sAMAccountName", "mail", "displayName"],
        searchbase=searchbase,
    )
    return [r for r in results if r.get("mail")]

@before("Get-DomainUser", priority=10)
def inject_enabled_filter(pv, args):
    if not args.ldapfilter:
        args.ldapfilter = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    return args

@after("Get-DomainUser", priority=20)
def add_pwage(pv, args, results):
    from datetime import datetime
    for entry in results:
        pwdlast = entry.get("pwdLastSet")
        if pwdlast and pwdlast != "0":
            try:
                age = datetime.now() - pwdlast
                entry["PasswordAge"] = f"{age.days} days"
            except Exception:
                pass
    return results

def setup(pv):
    print(f"[*] Custom enum plugin loaded for domain: {pv.domain}")
```
