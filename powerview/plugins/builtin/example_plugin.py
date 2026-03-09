from powerview.plugins import command, before, after


@command("Get-DomainUserEmail", args=["-Identity", "-SearchBase"],
         description="Get domain users with their email addresses")
def get_domainuseremail(pv, args=None, identity=None, searchbase=None):
    """Enumerate users and return only those with email addresses."""
    results = pv.get_domainuser(
        identity=identity or "*",
        properties=["sAMAccountName", "mail", "displayName"],
        searchbase=searchbase,
    )
    if results:
        return [r for r in results if r.get("mail")]
    return results
