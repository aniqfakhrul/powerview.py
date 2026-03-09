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
        logging.warning(f"Loading plugins from local directory: {local_dir}")
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

                logging.debug(f"Loaded plugin: {plugin_name}")

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
