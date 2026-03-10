#!/usr/bin/env python3
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from powerview.plugins import after, PowerviewPlugin
from powerview.utils.colors import bcolors

# for contributors, you dont have to include imports below. These are optional
if TYPE_CHECKING:
    from powerview.powerview import PowerView
from argparse import Namespace

plugin = PowerviewPlugin(
    name="Highlight",
    description="Highlight passwords found in user descriptions",
    author="aniqfakhrul",
)

PASSWORD_PATTERNS = re.compile(
    r'(pass(word|wd)?|pwd|cred(ential)?s?|secret|p@ss|p@\$\$)'
    r'\s*[:=\s]\s*\S+',
    re.IGNORECASE,
)

@after(["Sample-Get-DomainUser"], priority=10)
def highlight_pwd_in_description(pv: PowerView, args: Namespace, results: list[dict]) -> list[dict]:
    if not results:
        return results

    if hasattr(args, 'outfile') and args.outfile:
        return results

    for entry in results:
        attrs = entry.get("attributes", entry)
        desc = attrs.get("description")
        if not desc:
            continue
        text = desc if isinstance(desc, str) else str(desc)
        if PASSWORD_PATTERNS.search(text):
            attrs["description"] = f"{bcolors.FAIL}{text}{bcolors.ENDC}"

    return results
