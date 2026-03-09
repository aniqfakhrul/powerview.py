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
