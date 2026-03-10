from __future__ import annotations

import re
import sys
import logging
from argparse import Namespace
from typing import TYPE_CHECKING, Any, Callable, Optional

from tabulate import tabulate
from powerview.plugins import command, PowerviewPlugin
from powerview.utils.colors import bcolors

# for contributors, you dont have to include imports below. These are optional
if TYPE_CHECKING:
    from powerview.powerview import PowerView

plugin = PowerviewPlugin(
    name="Recon",
    description="Domain reconnaissance and enumeration summary",
    author="aniqfakhrul",
)

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


_USER_FILTER_KEYS = [
    'preauthnotrequired', 'passnotrequired', 'admincount', 'lockedout',
    'allowdelegation', 'disallowdelegation', 'trustedtoauth', 'rbcd',
    'shadowcred', 'spn', 'unconstrained', 'enabled', 'disabled',
    'password_expired', 'memberof', 'department', 'ldapfilter',
    'no_cache', 'no_vuln_check', 'raw',
]

_COMPUTER_FILTER_KEYS = [
    'unconstrained', 'trustedtoauth', 'laps', 'rbcd', 'shadowcred',
    'printers', 'spn', 'enabled', 'disabled', 'excludedcs', 'ldapfilter',
    'no_cache', 'no_vuln_check', 'raw', 'resolvesids', 'include_ip',
    'pre2k',
]


def _user_args(searchbase: Optional[str] = None, props: Optional[list[str]] = None, **flags: Any) -> Namespace:
    defaults = {k: None for k in _USER_FILTER_KEYS}
    defaults.update(properties=props or ["cn"], searchbase=searchbase, identity=None)
    defaults.update(flags)
    return Namespace(**defaults)


def _computer_args(searchbase: Optional[str] = None, props: Optional[list[str]] = None, **flags: Any) -> Namespace:
    defaults = {k: None for k in _COMPUTER_FILTER_KEYS}
    defaults.update(properties=props or ["cn"], searchbase=searchbase, identity=None)
    defaults.update(flags)
    return Namespace(**defaults)


def _count(results: Optional[list[dict]]) -> int:
    return len(results) if results else 0


def _safe_query(func: Callable[..., Optional[list[dict]]], **kwargs: Any) -> list[dict]:
    try:
        return func(**kwargs) or []
    except Exception as e:
        logging.warning(f"[Invoke-DomainRecon] Query failed: {e}")
        return []


def _extract(results: list[dict], keys: list[str]) -> list[list[str]]:
    rows = []
    for entry in results:
        attrs = entry.get("attributes", entry)
        row = []
        for k in keys:
            val = attrs.get(k, "")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            row.append(str(val) if val else "")
        rows.append(row)
    return rows


def _header(title: str, count: Optional[int | str] = None) -> None:
    if count is not None:
        title = f"{title} ({count})"
    colored = f"{bcolors.BOLD}{title}{bcolors.ENDC}"
    print(f"\n{colored}")
    print("─" * len(_ANSI_RE.sub('', title)))


def _color_count(n: int, threshold: int = 0) -> str:
    s = str(n)
    return f"{bcolors.FAIL}{s}{bcolors.ENDC}" if n > threshold else s


_CHECKS = [
    "Domain Info",
    "Users",
    "Computers",
    "Domain Controllers",
    "OUs",
    "GPOs",
    "Trusts",
    "CAs",
    "gMSAs",
    "Kerberoastable Users",
    "AS-REP Roastable",
    "Unconstrained Delegation",
    "Constrained Delegation",
    "RBCD",
    "Shadow Credentials",
    "LAPS",
    "Pre-Windows 2000 Computers",
    "AdminCount Users",
]

_PENDING = f"{bcolors.WARNING}...{bcolors.ENDC}"
_DONE_MARK = f"{bcolors.OKGREEN}✓{bcolors.ENDC}"


class _Progress:
    def __init__(self) -> None:
        self.tty: bool = hasattr(sys.stderr, 'isatty') and sys.stderr.isatty()
        self.lines: list[str] = list(_CHECKS)
        self.total: int = len(self.lines)

    def show(self) -> None:
        if not self.tty:
            return
        for name in self.lines:
            sys.stderr.write(f"  [ ] {name}: {_PENDING}\n")
        sys.stderr.flush()

    def update(self, index: int, count: int | str) -> None:
        if not self.tty:
            return
        lines_up = self.total - index
        sys.stderr.write(f"\033[{lines_up}A")
        sys.stderr.write(f"\r  [{_DONE_MARK}] {self.lines[index]}: {count}\033[K\n")
        sys.stderr.write(f"\033[{lines_up - 1}B")
        sys.stderr.flush()

    def clear(self) -> None:
        if not self.tty:
            return
        sys.stderr.write(f"\033[{self.total}A")
        for _ in range(self.total):
            sys.stderr.write(f"\033[K\n")
        sys.stderr.write(f"\033[{self.total}A")
        sys.stderr.flush()


@command("Invoke-DomainRecon", args=["-SearchBase"],
         description="Single-command domain reconnaissance summary")
def invoke_domainrecon(pv: PowerView, args: Optional[Namespace] = None, searchbase: Optional[str] = None) -> None:
    progress = _Progress()
    progress.show()
    idx = 0

    domain_info = _safe_query(pv.get_domain, properties=[
        "name", "dc", "ms-DS-MachineAccountQuota",
        "msDS-Behavior-Version", "lockoutThreshold",
        "minPwdLength", "maxPwdAge", "lockoutDuration",
    ])
    info_rows = []
    if domain_info:
        attrs = domain_info[0].get("attributes", {})
        info_rows = [
            ["Domain", attrs.get("name", "")],
            ["Functional Level", attrs.get("msDS-Behavior-Version", "")],
            ["MachineAccountQuota", attrs.get("ms-DS-MachineAccountQuota", "")],
            ["MinPwdLength", attrs.get("minPwdLength", "")],
            ["MaxPwdAge", attrs.get("maxPwdAge", "")],
            ["LockoutThreshold", attrs.get("lockoutThreshold", "")],
            ["LockoutDuration", attrs.get("lockoutDuration", "")],
        ]
    progress.update(idx, _DONE_MARK); idx += 1

    user_count = _count(_safe_query(pv.get_domainuser, args=_user_args(searchbase)))
    progress.update(idx, user_count); idx += 1

    computer_count = _count(_safe_query(pv.get_domaincomputer, args=_computer_args(searchbase)))
    progress.update(idx, computer_count); idx += 1

    dc_count = _count(_safe_query(pv.get_domaincontroller, properties=["cn"]))
    progress.update(idx, dc_count); idx += 1

    ou_count = _count(_safe_query(pv.get_domainou, properties=["cn"]))
    progress.update(idx, ou_count); idx += 1

    gpo_count = _count(_safe_query(pv.get_domaingpo, properties=["cn"]))
    progress.update(idx, gpo_count); idx += 1

    trust_count = _count(_safe_query(pv.get_domaintrust, properties=["cn"]))
    progress.update(idx, trust_count); idx += 1

    ca_count = _count(_safe_query(pv.get_domainca))
    progress.update(idx, ca_count); idx += 1

    gmsa_count = _count(_safe_query(pv.get_domaingmsa, properties=["cn"]))
    progress.update(idx, gmsa_count); idx += 1

    spn_props = ["sAMAccountName", "servicePrincipalName", "adminCount", "description"]
    kerberoastable = _safe_query(pv.get_domainuser, args=_user_args(searchbase, props=spn_props, spn=True))
    progress.update(idx, len(kerberoastable)); idx += 1

    asrep_props = ["sAMAccountName", "userAccountControl", "description"]
    asrep = _safe_query(pv.get_domainuser, args=_user_args(searchbase, props=asrep_props, preauthnotrequired=True))
    progress.update(idx, len(asrep)); idx += 1

    ud_props = ["sAMAccountName", "userAccountControl"]
    ud_users = _safe_query(pv.get_domainuser, args=_user_args(searchbase, props=ud_props, unconstrained=True))
    ud_computers = _safe_query(pv.get_domaincomputer, args=_computer_args(
        searchbase, props=ud_props, unconstrained=True, excludedcs=True,
    ))
    ud_all = ud_users + ud_computers
    progress.update(idx, len(ud_all)); idx += 1

    cd_props = ["sAMAccountName", "msDS-AllowedToDelegateTo"]
    cd_users = _safe_query(pv.get_domainuser, args=_user_args(searchbase, props=cd_props, trustedtoauth=True))
    cd_computers = _safe_query(pv.get_domaincomputer, args=_computer_args(searchbase, props=cd_props, trustedtoauth=True))
    cd_all = cd_users + cd_computers
    progress.update(idx, len(cd_all)); idx += 1

    rbcd_props = ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
    rbcd_users = _safe_query(pv.get_domainuser, args=_user_args(searchbase, props=rbcd_props, rbcd=True))
    rbcd_computers = _safe_query(pv.get_domaincomputer, args=_computer_args(searchbase, props=rbcd_props, rbcd=True))
    rbcd_all = rbcd_users + rbcd_computers
    progress.update(idx, len(rbcd_all)); idx += 1

    sc_query_props = ["sAMAccountName", "msDS-KeyCredentialLink"]
    sc_users = _safe_query(pv.get_domainuser, args=_user_args(searchbase, props=sc_query_props, shadowcred=True))
    sc_computers = _safe_query(pv.get_domaincomputer, args=_computer_args(searchbase, props=sc_query_props, shadowcred=True))
    sc_all = sc_users + sc_computers
    progress.update(idx, len(sc_all)); idx += 1

    laps_props = ["sAMAccountName", "ms-Mcs-AdmPwdExpirationTime", "msLaps-PasswordExpirationTime"]
    laps_computers = _safe_query(pv.get_domaincomputer, args=_computer_args(searchbase, props=laps_props, laps=True))
    progress.update(idx, len(laps_computers)); idx += 1

    pre2k_props = ["sAMAccountName"]
    pre2k_computers = _safe_query(pv.get_domaincomputer, args=_computer_args(searchbase, props=pre2k_props, pre2k=True))
    progress.update(idx, len(pre2k_computers)); idx += 1

    admin_props = ["sAMAccountName", "adminCount", "description"]
    admin_users = _safe_query(pv.get_domainuser, args=_user_args(searchbase, props=admin_props, admincount=True))
    progress.update(idx, len(admin_users)); idx += 1

    progress.clear()

    _header("Domain Info")
    print(tabulate(info_rows, tablefmt="plain"))

    _header("Object Counts")
    print(tabulate([
        ["Users", user_count],
        ["Computers", computer_count],
        ["Domain Controllers", dc_count],
        ["OUs", ou_count],
        ["GPOs", gpo_count],
        ["Trusts", trust_count],
        ["CAs", ca_count],
        ["gMSAs", gmsa_count],
    ], headers=["Category", "Count"], tablefmt="simple"))

    _header("Kerberoastable Users", _color_count(len(kerberoastable)))
    if kerberoastable:
        print(tabulate(_extract(kerberoastable, spn_props), headers=spn_props, tablefmt="simple"))

    _header("AS-REP Roastable Users", _color_count(len(asrep)))
    if asrep:
        print(tabulate(_extract(asrep, asrep_props), headers=asrep_props, tablefmt="simple"))

    _header("Unconstrained Delegation (excl. DCs)", _color_count(len(ud_all)))
    if ud_all:
        print(tabulate(_extract(ud_all, ud_props), headers=ud_props, tablefmt="simple"))

    _header("Constrained Delegation", _color_count(len(cd_all)))
    if cd_all:
        print(tabulate(_extract(cd_all, cd_props), headers=cd_props, tablefmt="simple"))

    _header("Resource-Based Constrained Delegation", _color_count(len(rbcd_all)))
    if rbcd_all:
        rbcd_display_headers = ["sAMAccountName", "AllowedToAct"]
        rbcd_rows = []
        for entry in rbcd_all:
            attrs = entry.get("attributes", entry)
            name = attrs.get("sAMAccountName", "")
            val = attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity", "")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            val = str(val) if val else ""
            if len(val) > 80:
                val = val[:77] + "..."
            rbcd_rows.append([name, val])
        print(tabulate(rbcd_rows, headers=rbcd_display_headers, tablefmt="simple"))

    _header("Shadow Credentials", _color_count(len(sc_all)))
    if sc_all:
        sc_display_headers = ["sAMAccountName", "Keys"]
        sc_rows = []
        for entry in sc_all:
            attrs = entry.get("attributes", entry)
            name = attrs.get("sAMAccountName", "")
            kcl = attrs.get("msDS-KeyCredentialLink", [])
            key_count = len(kcl) if isinstance(kcl, list) else (1 if kcl else 0)
            sc_rows.append([name, key_count])
        print(tabulate(sc_rows, headers=sc_display_headers, tablefmt="simple"))

    _header("LAPS Enabled Computers", len(laps_computers))
    if laps_computers:
        print(tabulate(_extract(laps_computers, laps_props), headers=laps_props, tablefmt="simple"))
    else:
        print("LAPS not deployed")

    _header("Pre-Windows 2000 Computers", _color_count(len(pre2k_computers)))
    if pre2k_computers:
        print(tabulate(_extract(pre2k_computers, pre2k_props), headers=pre2k_props, tablefmt="simple"))

    _header("AdminCount Users", len(admin_users))
    if admin_users:
        print(tabulate(_extract(admin_users, admin_props), headers=admin_props, tablefmt="simple"))

    print()
    return None
