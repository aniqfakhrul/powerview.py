#!/usr/bin/env python3

import os
import sys
import struct
import platform
import subprocess
import shutil

def get_terminal_size():
    """Get the current terminal size.
    
    Returns:
        tuple: (columns, rows) representing terminal dimensions
    """
    if os.name == 'nt':
        try:
            from ctypes import windll, create_string_buffer
            h = windll.kernel32.GetStdHandle(-11)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                import struct
                (_, _, _, _, _, left, top, right, bottom, _, _) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                width = right - left + 1
                height = bottom - top + 1
                return (width, height)
        except ImportError:
            pass
    
    # Try using get_terminal_size from shutil (Python 3.3+)
    try:
        return shutil.get_terminal_size()
    except AttributeError:
        pass
        
    # Try environment variables
    try:
        return (int(os.environ['COLUMNS']), int(os.environ['LINES']))
    except (KeyError, ValueError):
        pass

    # Default fallback
    return (80, 24)

def detect_terminal_environment():
    """Detect various aspects of the terminal environment.
    
    Returns:
        dict: A dictionary containing information about the terminal environment
    """
    env_info = {
        'os': platform.system(),
        'terminal_type': os.environ.get('TERM', 'unknown'),
        'colorterm': os.environ.get('COLORTERM', 'unknown'),
        'is_windows': os.name == 'nt',
        'size': get_terminal_size(),
        'supports_ansi': False,
        'supports_unicode': False,
        'is_ssh': 'SSH_CLIENT' in os.environ or 'SSH_TTY' in os.environ,
        'is_admin': False,
        'shell': os.environ.get('SHELL', os.environ.get('ComSpec', 'unknown'))
    }
    
    # Check for ANSI color support
    if env_info['is_windows']:
        # On Windows 10+ with proper terminal or ConEmu/cmder/Windows Terminal
        env_info['supports_ansi'] = (
            ('WT_SESSION' in os.environ) or 
            ('ConEmuANSI' in os.environ) or 
            ('ANSICON' in os.environ) or
            os.environ.get('TERM_PROGRAM') == 'vscode' or
            (sys.getwindowsversion()[0] >= 10 and sys.getwindowsversion()[2] >= 10586)
        )
    else:
        # On Unix-like systems
        env_info['supports_ansi'] = (
            os.environ.get('TERM', '').find('xterm') != -1 or
            os.environ.get('TERM', '').find('256color') != -1 or
            os.environ.get('COLORTERM', '').lower() in ('truecolor', '24bit', 'yes', 'true') or
            os.environ.get('TERM_PROGRAM') == 'vscode'
        )
    
    # Check for Unicode support
    env_info['supports_unicode'] = sys.stdout.encoding and 'utf' in sys.stdout.encoding.lower()
    
    # Check for admin/root privileges
    if env_info['is_windows']:
        try:
            import ctypes
            env_info['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            env_info['is_admin'] = False
    else:
        env_info['is_admin'] = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    # Try to detect terminal emulator
    if env_info['is_windows']:
        if 'WT_SESSION' in os.environ:
            env_info['terminal_emulator'] = 'Windows Terminal'
        elif 'ConEmuPID' in os.environ:
            env_info['terminal_emulator'] = 'ConEmu'
        elif 'CMDER_ROOT' in os.environ:
            env_info['terminal_emulator'] = 'Cmder'
        else:
            env_info['terminal_emulator'] = 'cmd.exe or PowerShell'
    else:
        # Try to detect terminal on Unix-like systems
        terminal = os.environ.get('TERM_PROGRAM', '')
        if terminal:
            env_info['terminal_emulator'] = terminal
        elif 'KONSOLE_VERSION' in os.environ:
            env_info['terminal_emulator'] = 'Konsole'
        elif 'GNOME_TERMINAL_SCREEN' in os.environ:
            env_info['terminal_emulator'] = 'GNOME Terminal'
        elif 'XTERM_VERSION' in os.environ:
            env_info['terminal_emulator'] = 'XTerm'
        else:
            env_info['terminal_emulator'] = 'Unknown'
    
    # Check proxy environment variables
    proxies = {}
    for proxy_var in ('http_proxy', 'https_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'):
        if proxy_var in os.environ:
            proxies[proxy_var] = os.environ[proxy_var]
    
    if proxies:
        env_info['proxy_settings'] = proxies
    
    return env_info

def is_headless():
    """Check if the terminal is running in a headless environment.
    
    Returns:
        bool: True if running in a headless environment, False otherwise
    """
    if os.name == 'nt':
        return False  # Windows is typically not headless
    
    # Check common headless environment indicators
    if 'DISPLAY' not in os.environ:
        return True
    
    # Check if running in Docker or container
    if os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv'):
        return True
    
    # Check if running in CI environment
    ci_vars = ['CI', 'TRAVIS', 'GITLAB_CI', 'GITHUB_ACTIONS', 'JENKINS_URL']
    if any(var in os.environ for var in ci_vars):
        return True
    
    return False

def supports_advanced_terminal_features():
    """Check if the terminal supports advanced features like cursor movement and styling.
    
    Returns:
        bool: True if the terminal supports advanced features, False otherwise
    """
    env = detect_terminal_environment()
    return env['supports_ansi'] and env['terminal_type'] not in ('dumb', 'unknown') 