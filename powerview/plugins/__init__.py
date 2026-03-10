from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class PowerviewPlugin:
    """
    Declare plugin-level metadata at the top of a plugin file.

    Usage:
        plugin = PowerviewPlugin(
            name="",
            description="",
            author="",
        )
    """
    name: str
    description: str = ""
    author: Optional[str] = None
    version: Optional[str] = None
    builtin: bool = field(default=False, repr=False)

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


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
    """
    Run before an existing command. Can modify args.

    Usage:
        @before("Get-DomainUser")
        @before(["Get-DomainUser", "Get-DomainComputer"])
    """
    def decorator(func):
        func._plugin_before = {
            "commands": [command_name] if isinstance(command_name, str) else list(command_name),
            "priority": priority,
        }
        return func
    return decorator


def after(command_name, priority=50):
    """
    Run after an existing command. Can modify results.

    Usage:
        @after("Get-DomainUser")
        @after(["Get-DomainUser", "Get-DomainComputer"])
    """
    def decorator(func):
        func._plugin_after = {
            "commands": [command_name] if isinstance(command_name, str) else list(command_name),
            "priority": priority,
        }
        return func
    return decorator
