from powerview.plugins import command


@command("Get-DomainAdmin", args=["-Identity", "-Properties", "-SearchBase", "-Server"],
         description="Get all privileged users with adminCount=1")
def get_domainadmin(pv, args=None, identity=None, properties=None, searchbase=None, server=None):
    """Find all domain users with adminCount=1."""
    props = properties or [
        "sAMAccountName", "memberOf", "adminCount",
        "pwdLastSet", "lastLogon", "userAccountControl",
        "servicePrincipalName", "description",
    ]
    ldapfilter = "(adminCount=1)"
    results = pv.get_domainuser(
        identity=identity or "*",
        properties=props,
        searchbase=searchbase,
    )
    if results:
        return [r for r in results
                if str(r.get("attributes", r).get("adminCount", "")) == "1"]
    return results


@command("Get-StaleComputer", args=["-Days", "-Properties", "-SearchBase", "-Server"],
         description="Find computer accounts that haven't logged in for N days (default: 90)")
def get_stalecomputer(pv, args=None, days=None, properties=None, searchbase=None, server=None):
    """Find computer accounts inactive for N days based on lastLogonTimestamp."""
    from datetime import datetime, timedelta, timezone
    threshold_days = int(days) if days else 90
    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)

    props = properties or [
        "sAMAccountName", "dNSHostName", "lastLogonTimestamp",
        "operatingSystem", "userAccountControl", "description",
    ]
    results = pv.get_domaincomputer(properties=props, searchbase=searchbase)
    if not results:
        return results

    stale = []
    for entry in results:
        attrs = entry.get("attributes", entry)
        last_logon = attrs.get("lastLogonTimestamp")
        if not last_logon:
            stale.append(entry)
            continue
        if isinstance(last_logon, datetime):
            if last_logon.tzinfo is None:
                last_logon = last_logon.replace(tzinfo=timezone.utc)
            if last_logon < cutoff:
                stale.append(entry)
    return stale


@command("Get-KerberoastableUser", args=["-Identity", "-Properties", "-SearchBase", "-Server"],
         description="Find kerberoastable users (non-machine accounts with SPNs)")
def get_kerberoastableuser(pv, args=None, identity=None, properties=None, searchbase=None, server=None):
    """Find user accounts with servicePrincipalName set (kerberoastable)."""
    props = properties or [
        "sAMAccountName", "servicePrincipalName", "adminCount",
        "memberOf", "pwdLastSet", "lastLogon", "description",
    ]
    results = pv.get_domainuser(
        identity=identity or "*",
        properties=props,
        searchbase=searchbase,
    )
    if results:
        return [r for r in results
                if r.get("attributes", r).get("servicePrincipalName")]
    return results
