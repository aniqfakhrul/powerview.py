# Plugin System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a decorator-based plugin system that lets users add new commands and hook before/after existing commands via single `.py` files.

**Architecture:** Three-component system: decorators (`@command`, `@before`, `@after`) stash metadata on functions, a `PluginRegistry` stores registered commands/hooks, and a loader discovers `.py` files from three paths (builtin, user home, CWD). The `execute()` method in `powerview.py` is modified to run hooks. Plugin commands are injected into argparse and the tab completer at startup.

**Tech Stack:** Python stdlib (`importlib.util`, `os`, `inspect`), no new dependencies.

---

### Task 1: Create the decorator module

**Files:**
- Create: `powerview/plugins/__init__.py`

**Step 1: Write the decorator module**

```python
# powerview/plugins/__init__.py

def command(name, args=None, description=None):
    """Register a function as a new PowerView command.

    Usage:
        @command("Get-CustomThing", args=["-Identity", "-Properties"])
        def get_customthing(pv, args=None, identity=None, properties=[]):
            ...
    """
    def decorator(func):
        func._plugin_command = {
            "name": name,
            "args": args or [],
            "description": description or func.__doc__ or "",
        }
        return func
    return decorator


def before(command_name, priority=50):
    """Run before an existing command. Can modify args.

    Usage:
        @before("Get-DomainUser")
        def filter_disabled(pv, args):
            return args
    """
    def decorator(func):
        func._plugin_before = {
            "command": command_name,
            "priority": priority,
        }
        return func
    return decorator


def after(command_name, priority=50):
    """Run after an existing command. Can modify results.

    Usage:
        @after("Get-DomainUser")
        def enrich_results(pv, args, results):
            return results
    """
    def decorator(func):
        func._plugin_after = {
            "command": command_name,
            "priority": priority,
        }
        return func
    return decorator
```

**Step 2: Verify the file is importable**

Run: `cd /home/user/dev/powerview-main && python3 -c "from powerview.plugins import command, before, after; print('OK')"`
Expected: `OK`

**Step 3: Commit**

```bash
git add powerview/plugins/__init__.py
git commit -m "feat(plugins): add decorator module for @command, @before, @after"
```

---

### Task 2: Create the PluginRegistry

**Files:**
- Create: `powerview/plugins/registry.py`

**Step 1: Write the registry**

```python
# powerview/plugins/registry.py

import logging


class PluginRegistry:
    def __init__(self):
        self.commands = {}
        self.before_hooks = {}
        self.after_hooks = {}

    def register_command(self, name, func, args=None, description=""):
        if name in self.commands:
            logging.warning(f"Plugin command '{name}' already registered, overwriting")
        self.commands[name] = {
            "func": func,
            "args": args or [],
            "description": description,
        }

    def register_before_hook(self, command_name, func, priority=50):
        self.before_hooks.setdefault(command_name, []).append((priority, func))
        self.before_hooks[command_name].sort(key=lambda x: x[0])

    def register_after_hook(self, command_name, func, priority=50):
        self.after_hooks.setdefault(command_name, []).append((priority, func))
        self.after_hooks[command_name].sort(key=lambda x: x[0])

    def get_before_hooks(self, command_name):
        return [func for _, func in self.before_hooks.get(command_name, [])]

    def get_after_hooks(self, command_name):
        return [func for _, func in self.after_hooks.get(command_name, [])]
```

**Step 2: Verify import**

Run: `cd /home/user/dev/powerview-main && python3 -c "from powerview.plugins.registry import PluginRegistry; r = PluginRegistry(); print('OK')"`
Expected: `OK`

**Step 3: Commit**

```bash
git add powerview/plugins/registry.py
git commit -m "feat(plugins): add PluginRegistry for commands and hooks"
```

---

### Task 3: Create the plugin loader

**Files:**
- Create: `powerview/plugins/loader.py`
- Create: `powerview/plugins/builtin/__init__.py` (empty, makes it a package)

**Step 1: Create the builtin directory**

```bash
mkdir -p powerview/plugins/builtin
touch powerview/plugins/builtin/__init__.py
```

**Step 2: Write the loader**

```python
# powerview/plugins/loader.py

import os
import importlib.util
import logging


PLUGIN_PATHS = [
    os.path.join(os.path.dirname(__file__), 'builtin'),
    os.path.join(os.path.expanduser('~'), '.powerview', 'plugins'),
]


def _get_plugin_paths():
    """Return plugin search paths. Adds CWD/plugins/ if it exists."""
    paths = list(PLUGIN_PATHS)
    local_dir = os.path.join(os.getcwd(), 'plugins')
    if os.path.isdir(local_dir):
        paths.append(local_dir)
    return paths


def load_plugins(registry, pv):
    """Scan plugin paths, load .py files, register commands and hooks."""
    for plugin_dir in _get_plugin_paths():
        if not os.path.isdir(plugin_dir):
            continue

        for filename in sorted(os.listdir(plugin_dir)):
            if not filename.endswith('.py') or filename.startswith('_'):
                continue

            filepath = os.path.join(plugin_dir, filename)
            plugin_name = filename[:-3]

            try:
                spec = importlib.util.spec_from_file_location(
                    f"powerview.plugins.loaded.{plugin_name}", filepath
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                _register_from_module(registry, module)

                if hasattr(module, 'setup') and callable(module.setup):
                    module.setup(pv)

                logging.info(f"Loaded plugin: {plugin_name}")

            except Exception as e:
                logging.error(f"Failed to load plugin {filename}: {e}")

    return registry


def _register_from_module(registry, module):
    """Scan a module for decorated functions and register them."""
    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if not callable(obj):
            continue

        if hasattr(obj, '_plugin_command'):
            meta = obj._plugin_command
            registry.register_command(
                meta["name"], obj, meta["args"], meta["description"]
            )

        if hasattr(obj, '_plugin_before'):
            meta = obj._plugin_before
            registry.register_before_hook(
                meta["command"], obj, meta["priority"]
            )

        if hasattr(obj, '_plugin_after'):
            meta = obj._plugin_after
            registry.register_after_hook(
                meta["command"], obj, meta["priority"]
            )
```

**Step 3: Verify import**

Run: `cd /home/user/dev/powerview-main && python3 -c "from powerview.plugins.loader import load_plugins; print('OK')"`
Expected: `OK`

**Step 4: Commit**

```bash
git add powerview/plugins/loader.py powerview/plugins/builtin/__init__.py
git commit -m "feat(plugins): add plugin loader with three-path discovery"
```

---

### Task 4: Create example builtin plugin

**Files:**
- Create: `powerview/plugins/builtin/example_plugin.py`

**Step 1: Write the example plugin**

```python
# powerview/plugins/builtin/example_plugin.py
#
# Example plugin demonstrating the plugin API.
# Copy this to ~/.powerview/plugins/ and modify it.

from powerview.plugins import command, before, after


@command("Get-DomainUserEmail", args=["-Identity", "-SearchBase"],
         description="Get domain users with their email addresses")
def get_domainuseremail(pv, args=None, identity=None, searchbase=None):
    """Enumerate users and return only those with email addresses."""
    results = pv.get_domainuser(
        identity=identity or "*",
        properties=["sAMAccountName", "mail", "displayName"],
        searchbase=searchbase,
    )
    if results:
        return [r for r in results if r.get("mail")]
    return results
```

**Step 2: Commit**

```bash
git add powerview/plugins/builtin/example_plugin.py
git commit -m "feat(plugins): add example builtin plugin"
```

---

### Task 5: Integrate plugin hooks into PowerView.execute()

**Files:**
- Modify: `powerview/powerview.py:76-110` (add `plugin_registry` attribute to `__init__`)
- Modify: `powerview/powerview.py:401-410` (modify `execute()` to run hooks)

**Step 1: Add plugin_registry attribute to PowerView.__init__**

In `powerview/powerview.py`, after line 110 (`self.domain_instances = {}`), add:

```python
        self.plugin_registry = None
```

**Step 2: Modify execute() to support hooks and plugin commands**

Replace the existing `execute()` method at lines 401-410 with:

```python
	def execute(self, args):
		module_name = args.module

		# Run before hooks
		if self.plugin_registry:
			for hook in self.plugin_registry.get_before_hooks(module_name):
				modified = hook(self, args)
				if modified is not None:
					args = modified

		# Try plugin command first, then core method
		if self.plugin_registry and module_name in self.plugin_registry.commands:
			result = self.plugin_registry.commands[module_name]["func"](self, args=args)
		else:
			method_name = module_name.replace('-', '_').lower()
			method = getattr(self, method_name, None)
			if not method:
				raise ValueError(f"Method {method_name} not found in PowerView")
			method_signature = inspect.signature(method)
			method_params = method_signature.parameters
			method_args = {k: v for k, v in vars(args).items() if k in method_params}
			result = method(**method_args)

		# Run after hooks
		if self.plugin_registry:
			for hook in self.plugin_registry.get_after_hooks(module_name):
				modified = hook(self, args, result)
				if modified is not None:
					result = modified

		return result
```

**Step 3: Verify the file is still importable**

Run: `cd /home/user/dev/powerview-main && python3 -c "from powerview.powerview import PowerView; print('OK')"`
Expected: `OK`

**Step 4: Commit**

```bash
git add powerview/powerview.py
git commit -m "feat(plugins): integrate hook execution into PowerView.execute()"
```

---

### Task 6: Integrate plugin loading into CLI REPL

**Files:**
- Modify: `powerview/__init__.py:10` (add imports)
- Modify: `powerview/__init__.py:63-68` (load plugins after PowerView init)
- Modify: `powerview/__init__.py:469` (add plugin command dispatch fallback before output formatting)

**Step 1: Add imports**

After line 18 (`from powerview.utils.parsers import powerview_arg_parse, arg_parse`), add:

```python
from powerview.plugins.registry import PluginRegistry
from powerview.plugins.loader import load_plugins
```

**Step 2: Load plugins after PowerView initialization**

After line 68 (`comp.setup_completer()`), add the plugin loading block:

```python
        # Load plugins
        plugin_registry = PluginRegistry()
        load_plugins(plugin_registry, powerview)
        powerview.plugin_registry = plugin_registry

        # Inject plugin commands into completer
        from powerview.utils.completer import COMMANDS
        for cmd_name, cmd_info in plugin_registry.commands.items():
            COMMANDS[cmd_name] = cmd_info["args"]
```

**Step 3: Add plugin command dispatch fallback**

In the if-elif dispatch chain, before the output formatting block (before line 471 `if entries:`), add the plugin fallback. Insert after the `exit` elif block (after line 469):

```python
                            elif pv.plugin_registry and pv_args.module in pv.plugin_registry.commands:
                                entries = pv.execute(pv_args)
```

**Step 4: Verify the file is still importable**

Run: `cd /home/user/dev/powerview-main && python3 -c "from powerview import main; print('OK')"`
Expected: `OK`

**Step 5: Commit**

```bash
git add powerview/__init__.py
git commit -m "feat(plugins): load plugins at CLI startup, inject into completer and dispatch"
```

---

### Task 7: Add plugin commands to argparse dynamically

**Files:**
- Modify: `powerview/utils/parsers.py` (add function to register plugin subparsers)

**Step 1: Find the subparsers object**

Read `powerview/utils/parsers.py` to find where `subparsers = parser.add_subparsers(dest='module')` is defined and the function signature.

**Step 2: Add a function to register plugin commands into argparse**

At the end of `parsers.py`, add:

```python
def register_plugin_commands(plugin_registry):
    """Register plugin commands as argparse subparsers.

    Called at startup after plugins are loaded. Adds each plugin command
    as a subparser so argparse recognizes it and parses its arguments.
    """
    global _plugin_registry
    _plugin_registry = plugin_registry
```

Actually, looking at `parsers.py` more carefully — `powerview_arg_parse()` creates a **new parser on every call** (line 134+). So plugin commands need to be registered inside that function.

**Revised approach:** Add a module-level variable that `powerview_arg_parse()` checks after building subparsers.

At the top of `parsers.py`, add:

```python
_plugin_registry = None

def set_plugin_registry(registry):
    """Set the plugin registry for argument parsing."""
    global _plugin_registry
    _plugin_registry = registry
```

Then inside `powerview_arg_parse()`, after all the existing `subparsers.add_parser(...)` calls but before `args = parser.parse_args(cmd)`, add:

```python
    # Register plugin commands
    if _plugin_registry:
        for cmd_name, cmd_info in _plugin_registry.commands.items():
            plugin_parser = subparsers.add_parser(cmd_name, exit_on_error=False)
            for arg in cmd_info["args"]:
                dest = arg.lstrip('-').lower().replace('-', '_')
                plugin_parser.add_argument(arg, action='store', dest=dest)
```

**Step 3: Update CLI init to call set_plugin_registry**

In `powerview/__init__.py`, after the plugin loading block (added in Task 6), add:

```python
        from powerview.utils.parsers import set_plugin_registry
        set_plugin_registry(plugin_registry)
```

**Step 4: Verify the file is still importable**

Run: `cd /home/user/dev/powerview-main && python3 -c "from powerview.utils.parsers import powerview_arg_parse; print('OK')"`
Expected: `OK`

**Step 5: Commit**

```bash
git add powerview/utils/parsers.py powerview/__init__.py
git commit -m "feat(plugins): register plugin commands in argparse dynamically"
```

---

### Task 8: Ensure plugins are included in package builds

**Files:**
- Modify: `pyproject.toml`

**Step 1: Verify setuptools finds the plugins package**

The existing config has `include-package-data = true` and uses auto-discovery. Since `powerview/plugins/` has `__init__.py` and `powerview/plugins/builtin/` has `__init__.py`, setuptools should auto-discover them.

Verify by running:

Run: `cd /home/user/dev/powerview-main && python3 -c "from setuptools import find_packages; print([p for p in find_packages() if 'plugin' in p])"`
Expected: Should include `powerview.plugins` and `powerview.plugins.builtin`

**Step 2: If not found, add explicit package config to pyproject.toml**

Add after the existing `[tool.setuptools]` section:

```toml
[tool.setuptools.packages.find]
include = ["powerview*"]
```

**Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "feat(plugins): ensure plugin packages included in builds"
```

---

### Task 9: Create ~/.powerview/plugins/ directory and test end-to-end

**Files:**
- Create: test plugin at `~/.powerview/plugins/test_plugin.py` (temporary, for manual testing)

**Step 1: Create user plugin directory**

```bash
mkdir -p ~/.powerview/plugins
```

**Step 2: Create a test plugin**

```python
# ~/.powerview/plugins/test_plugin.py
from powerview.plugins import command

@command("Test-Plugin", args=["-Message"], description="Test that plugins work")
def test_plugin(pv, args=None, message=None):
    """Simple test command."""
    return [{"status": "Plugin system working", "message": message or "hello", "domain": pv.domain}]
```

**Step 3: Verify plugin loads**

Run powerview with `--stack-trace` and check that "Loaded plugin: test_plugin" appears in debug output. Then run `Test-Plugin -Message "it works"` in the REPL.

**Step 4: Clean up test plugin**

```bash
rm ~/.powerview/plugins/test_plugin.py
```

**Step 5: Commit (no files to commit — manual test only)**

---

### Task 10: Final verification and cleanup

**Step 1: Verify all three plugin paths work**

1. Builtin plugin: `Get-DomainUserEmail` should appear in tab completion
2. User plugin: Drop a `.py` in `~/.powerview/plugins/`, verify it loads
3. CWD plugin: Create `./plugins/test.py` at project root, verify it loads when running `python3 powerview.py`

**Step 2: Verify installed mode works**

```bash
cd /home/user/dev/powerview-main
uv tool install . --force
powerview --help  # Should not crash
```

**Step 3: Final commit**

```bash
git add -A
git commit -m "feat(plugins): complete plugin system with decorator-based registration"
```
