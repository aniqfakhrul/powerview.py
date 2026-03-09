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

    def register_command(self, name, func, args=None, description=""):
        core = _load_core_commands()
        if name.casefold() in core:
            logging.warning(f"Plugin command '{name}' shadows a core command and will be ignored from the REPL")
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

    def find_command(self, name):
        """Case-insensitive command lookup. Returns (canonical_name, cmd_info) or (None, None)."""
        if name in self.commands:
            return name, self.commands[name]
        name_lower = name.casefold()
        for cmd_name, cmd_info in self.commands.items():
            if cmd_name.casefold() == name_lower:
                return cmd_name, cmd_info
        return None, None

    def get_before_hooks(self, command_name):
        hooks = []
        name_lower = command_name.casefold()
        for key, hook_list in self.before_hooks.items():
            if key.casefold() == name_lower:
                hooks.extend(hook_list)
        hooks.sort(key=lambda x: x[0])
        return [func for _, func in hooks]

    def get_after_hooks(self, command_name):
        hooks = []
        name_lower = command_name.casefold()
        for key, hook_list in self.after_hooks.items():
            if key.casefold() == name_lower:
                hooks.extend(hook_list)
        hooks.sort(key=lambda x: x[0])
        return [func for _, func in hooks]
