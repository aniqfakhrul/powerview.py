import os
import inspect
import importlib.util
import logging

from powerview.plugins import PowerviewPlugin

BUILTIN_PATH = os.path.join(os.path.dirname(__file__), 'builtin')

PLUGIN_PATHS = [
    BUILTIN_PATH,
    os.path.join(os.path.expanduser('~'), '.powerview', 'plugins'),
]

def _get_plugin_paths():
    return list(PLUGIN_PATHS)

def load_plugins(registry, pv):
    for plugin_dir in _get_plugin_paths():
        if not os.path.isdir(plugin_dir):
            continue

        is_builtin = os.path.realpath(plugin_dir) == os.path.realpath(BUILTIN_PATH)

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

                if not _plugin_is_sane(module, filepath):
                    continue

                # Extract PowerviewPlugin metadata if declared
                plugin_meta = _find_plugin_meta(module)
                if plugin_meta:
                    plugin_meta.builtin = is_builtin
                else:
                    plugin_meta = PowerviewPlugin(name=plugin_name)
                    plugin_meta.builtin = is_builtin

                registry.register_plugin(plugin_name, plugin_meta)
                _register_from_module(registry, module, source=plugin_name)

                if hasattr(module, 'setup') and callable(module.setup):
                    module.setup(pv)

                logging.debug(f"Loaded plugin: {plugin_name}")

            except Exception as e:
                logging.error(f"Failed to load plugin {filename}: {e}")

    return registry


def _plugin_is_sane(module, filepath):
    errors = []
    has_command = False
    has_hook = False

    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if not callable(obj) or not hasattr(obj, '__call__'):
            continue

        if hasattr(obj, '_plugin_command'):
            has_command = True
            params = list(inspect.signature(obj).parameters.keys())
            if not params or params[0] != 'pv':
                errors.append(f"@command '{obj._plugin_command['name']}': first parameter must be 'pv', got '{params[0] if params else 'none'}'")

        if hasattr(obj, '_plugin_before'):
            has_hook = True
            params = list(inspect.signature(obj).parameters.keys())
            if len(params) < 2 or params[0] != 'pv' or params[1] != 'args':
                errors.append(f"@before hook '{attr_name}': signature must start with (pv, args), got ({', '.join(params[:2])})")

        if hasattr(obj, '_plugin_after'):
            has_hook = True
            params = list(inspect.signature(obj).parameters.keys())
            if len(params) < 3 or params[0] != 'pv' or params[1] != 'args' or params[2] != 'results':
                errors.append(f"@after hook '{attr_name}': signature must start with (pv, args, results), got ({', '.join(params[:3])})")

    if not has_command and not has_hook:
        logging.warning(f"Plugin {filepath} has no @command or @before/@after hooks — skipping")
        return False

    for err in errors:
        logging.error(f"Plugin {filepath}: {err}")

    if errors:
        return False

    return True


def _find_plugin_meta(module):
    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if isinstance(obj, PowerviewPlugin):
            return obj
    return None

def _register_from_module(registry, module, source=None):
    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if not callable(obj):
            continue

        if hasattr(obj, '_plugin_command'):
            meta = obj._plugin_command
            registry.register_command(
                meta["name"], obj, meta["args"], meta["description"],
                source=source,
            )

        if hasattr(obj, '_plugin_before'):
            meta = obj._plugin_before
            for cmd in meta["commands"]:
                registry.register_before_hook(cmd, obj, meta["priority"], source=source)

        if hasattr(obj, '_plugin_after'):
            meta = obj._plugin_after
            for cmd in meta["commands"]:
                registry.register_after_hook(cmd, obj, meta["priority"], source=source)
