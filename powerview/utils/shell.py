#!/usr/bin/env python3
import shutil
from powerview.utils.colors import bcolors, Gradient

RL_START = "\001"
RL_END = "\002"

def _rl(escape):
    """Wrap an ANSI escape in readline invisible markers so it doesn't
    count toward the visible prompt width (prevents line-wrap glitches)."""
    return f"{RL_START}{escape}{RL_END}"

def _safe(callable_obj, default=None):
    try:
        return callable_obj()
    except Exception:
        return default

def _get_keepalive_indicator(conn):
    pool = getattr(conn, '_connection_pool', None)
    interval = getattr(pool, 'keepalive_interval', 0) if pool else 0
    if isinstance(interval, int) and interval > 0:
        return f" {_rl(bcolors.OKGREEN)}[💓:{interval}s]{_rl(bcolors.ENDC)}"
    return ""

def _gradient_text(text, rgb_start, rgb_end):
    colors = Gradient.generate_gradient_colors(rgb_start, rgb_end, len(text))
    out = ""
    for i, ch in enumerate(text):
        r, g, b = colors[i]
        color = f'\033[38;2;{r};{g};{b}m'
        out += f"{_rl(color)}{ch}{_rl(bcolors.ENDC)}"
    return out

def get_prompt(powerview, current_target_domain=None, using_cache=False, args=None):
    init_proto = _safe(lambda: powerview.conn.get_proto(), "LDAP")
    server_dns = _safe(lambda: powerview.get_server_dns(), "<server>")
    nameserver = _safe(lambda: powerview.conn.get_nameserver(), None)
    obfuscate = getattr(args, 'obfuscate', False) if args else False

    is_admin = False
    if args and not getattr(args, 'no_admin_check', False):
        is_admin = _safe(lambda: powerview.get_admin_status(), False)

    cur_user = _safe(lambda: powerview.conn.who_am_i(), "")
    if is_admin:
        cur_user = f"{_rl(bcolors.WARNING)}{cur_user}{_rl(bcolors.ENDC)}"

    mcp_running = False
    web_running = False
    if args:
        if getattr(args, 'mcp', False) and hasattr(powerview, 'mcp_server'):
            mcp_running = _safe(lambda: powerview.mcp_server.get_status(), False)
        if getattr(args, 'web', False) and hasattr(powerview, 'api_server'):
            web_running = _safe(lambda: powerview.api_server.get_status(), False)

    channel_binding_active = getattr(powerview.conn, 'use_channel_binding', False)
    ldap_signing_active = getattr(powerview.conn, 'use_sign_and_seal', False)
    keepalive_indicator = _get_keepalive_indicator(powerview.conn)

    domain_indicator = f" {_rl(bcolors.BOLD + bcolors.FAIL)}[→ {current_target_domain}]{_rl(bcolors.ENDC)}" if current_target_domain else ""
    cache_indicator = f" {_rl(bcolors.WARNING)}[CACHED]{_rl(bcolors.ENDC)}" if using_cache else ""

    mcp_indicator = ""
    if mcp_running:
        mcp_indicator = f" {_rl(bcolors.BOLD)}{_gradient_text('[MCP]', [138,43,226], [0,191,255])}{_rl(bcolors.ENDC)}"

    web_indicator = ""
    if web_running:
        web_indicator = f" {_rl(bcolors.OKBLUE)}[WEB:{args.web_host}:{args.web_port}]{_rl(bcolors.ENDC)}"

    security_indicators = ""
    if channel_binding_active:
        security_indicators += "📦 "
    if ldap_signing_active:
        security_indicators += "🔒 "
    if obfuscate:
        security_indicators += "😈 "

    try:
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
    except Exception:
        width = 100

    if width < 100:
        return (
            f"{_rl(bcolors.OKBLUE)}PV{_rl(bcolors.ENDC)} "
            f"{security_indicators}"
            f"{_rl(bcolors.WARNING + bcolors.BOLD)}{init_proto}{_rl(bcolors.ENDC)} "
            f"[{_rl(bcolors.OKCYAN)}{server_dns}{_rl(bcolors.ENDC)}] "
            f"[{cur_user}] "
            f"NS:{nameserver if nameserver else '<auto>'}"
            f"{keepalive_indicator}"
            f"{mcp_indicator}{web_indicator}{domain_indicator}{cache_indicator} "
            f"{_rl(bcolors.OKGREEN)}❯{_rl(bcolors.ENDC)} "
        )

    return (
        f"{_rl(bcolors.OKBLUE)}╭─{_rl(bcolors.ENDC)}"
        f"{security_indicators}"
        f"{_rl(bcolors.WARNING + bcolors.BOLD)}{init_proto}{_rl(bcolors.ENDC)}"
        f"{_rl(bcolors.OKBLUE)}─[{_rl(bcolors.ENDC)}{_rl(bcolors.OKCYAN)}{server_dns}{_rl(bcolors.ENDC)}{_rl(bcolors.OKBLUE)}]{_rl(bcolors.ENDC)}"
        f"{_rl(bcolors.OKBLUE)}─[{_rl(bcolors.ENDC)}{cur_user}{_rl(bcolors.OKBLUE)}]{_rl(bcolors.ENDC)}"
        f"{_rl(bcolors.OKBLUE)}-[NS:{nameserver if nameserver else '<auto>'}]{_rl(bcolors.ENDC)}"
        f"{keepalive_indicator}"
        f"{mcp_indicator}"
        f"{web_indicator}"
        f"{domain_indicator}"
        f"{cache_indicator}"
        f"\n{_rl(bcolors.OKBLUE)}╰─{_rl(bcolors.OKGREEN)} ❯{_rl(bcolors.ENDC)} "
    )
