import logging


CORE_COMMANDS = None

def _load_core_commands():
    global CORE_COMMANDS
    if CORE_COMMANDS is None:
        from powerview.utils.completer import COMMANDS
        CORE_COMMANDS = {k.casefold() for k in COMMANDS}
    return CORE_COMMANDS

class PluginRegistry:
    def __init__(self):
        self.commands = {}
        self.before_hooks = {}
        self.after_hooks = {}
        self.disabled_plugins = set()
        self.plugin_meta = {} 
        self.plugin_sources = {}

    def register_plugin(self, source, meta):
        self.plugin_meta[source] = meta

    def _track_source(self, source, kind, name):
        if source:
            entry = self.plugin_sources.setdefault(source, {"commands": [], "before_hooks": [], "after_hooks": []})
            entry[kind].append(name)

    def register_command(self, name, func, args=None, description="", source=None):
        core = _load_core_commands()
        if name.casefold() in core:
            logging.warning(f"Plugin command '{name}' shadows a core command — the core command takes priority in the REPL")
            return
        if name in self.commands:
            old_source = self.commands[name].get("source")
            logging.warning(f"Plugin command '{name}' already registered, overwriting")
            if old_source and old_source in self.plugin_sources:
                cmds = self.plugin_sources[old_source]["commands"]
                if name in cmds:
                    cmds.remove(name)
        self.commands[name] = {
            "func": func,
            "args": args or [],
            "description": description,
            "source": source,
        }
        self._track_source(source, "commands", name)

    def register_before_hook(self, command_name, func, priority=50, source=None):
        self.before_hooks.setdefault(command_name, []).append((priority, func, source))
        self.before_hooks[command_name].sort(key=lambda x: x[0])
        self._track_source(source, "before_hooks", command_name)

    def register_after_hook(self, command_name, func, priority=50, source=None):
        self.after_hooks.setdefault(command_name, []).append((priority, func, source))
        self.after_hooks[command_name].sort(key=lambda x: x[0])
        self._track_source(source, "after_hooks", command_name)

    def find_command(self, name):
        match_name, match_info = None, None
        if name in self.commands:
            match_name, match_info = name, self.commands[name]
        else:
            name_lower = name.casefold()
            for cmd_name, cmd_info in self.commands.items():
                if cmd_name.casefold() == name_lower:
                    match_name, match_info = cmd_name, cmd_info
                    break
        if match_info and match_info.get("source") in self.disabled_plugins:
            return None, None
        return match_name, match_info

    def get_before_hooks(self, command_name):
        hooks = []
        name_lower = command_name.casefold()
        for key, hook_list in self.before_hooks.items():
            if key.casefold() == name_lower:
                hooks.extend(hook_list)
        hooks.sort(key=lambda x: x[0])
        return [func for _, func, src in hooks if src not in self.disabled_plugins]

    def get_after_hooks(self, command_name):
        hooks = []
        name_lower = command_name.casefold()
        for key, hook_list in self.after_hooks.items():
            if key.casefold() == name_lower:
                hooks.extend(hook_list)
        hooks.sort(key=lambda x: x[0])
        return [func for _, func, src in hooks if src not in self.disabled_plugins]

    def list_plugins(self):
        plugins = []
        for source, items in sorted(self.plugin_sources.items()):
            meta = self.plugin_meta.get(source)
            entry = {
                "name": meta.name if meta else source,
                "source": source,
                "description": meta.description if meta else "",
                "builtin": meta.builtin if meta else False,
                "enabled": source not in self.disabled_plugins,
                "commands": items.get("commands", []),
                "before_hooks": items.get("before_hooks", []),
                "after_hooks": items.get("after_hooks", []),
            }
            if meta and meta.author:
                entry["author"] = meta.author
            if meta and meta.version:
                entry["version"] = meta.version
            plugins.append(entry)
        return plugins

    def _resolve_plugin(self, name):
        name_lower = name.casefold()
        for source in self.plugin_sources:
            if source.casefold() == name_lower:
                return source
            meta = self.plugin_meta.get(source)
            if meta and meta.name.casefold() == name_lower:
                return source
        return None

    def enable_plugin(self, name):
        source = self._resolve_plugin(name)
        if source:
            self.disabled_plugins.discard(source)
            logging.info(f"Plugin '{source}' enabled")
            return True
        return False

    def disable_plugin(self, name):
        source = self._resolve_plugin(name)
        if source:
            self.disabled_plugins.add(source)
            logging.info(f"Plugin '{source}' disabled")
            return True
        return False
