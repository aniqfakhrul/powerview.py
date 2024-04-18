"""Service4User Extension"""
import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.named_tuples import AcquireCredResult, AddCredResult
    from gssapi.raw.names import Name
    from gssapi.raw.oids import OID


def acquire_cred_impersonate_name(
    impersonator_cred: "Creds",
    name: "Name",
    lifetime: t.Optional[int] = None,
    mechs: t.Optional[t.Iterable["OID"]] = None,
    usage: str = 'initiate',
) -> "AcquireCredResult":
    """Acquire credentials by impersonating another name.

    This method is one of the ways to use S4U2Self.  It acquires credentials
    by impersonating another name using a set of proxy credentials.  The
    impersonator credentials must have a usage of 'both' or 'initiate'.

    Args:
        impersonator_cred (~gssapi.raw.creds.Creds): the credentials with
            permissions to impersonate the target name
        name (~gssapi.raw.names.Name): the name to impersonate
        lifetime (int): the lifetime for the credentials (or None for
            indefinite) in seconds
        mechs (~gssapi.raw.types.MechType): the desired mechanisms for which
            the credentials should work (or None for the default set)
        usage (str): the usage type for the credentials: may be
            'initiate', 'accept', or 'both'

    Returns:
        AcquireCredResult: the resulting credentials, the actual mechanisms
        with which they may be used, and their actual lifetime in seconds (or
        None for indefinite or not support)

    Raises:
        ~gssapi.exceptions.GSSError
    """


def add_cred_impersonate_name(
    input_cred: "Creds",
    impersonator_cred: "Creds",
    name: "Name",
    mech: "OID",
    usage: str = 'initiate',
    init_lifetime: t.Optional[int] = None,
    accept_lifetime: t.Optional[int] = None,
) -> "AddCredResult":
    """Add a credentials element to a credential by impersonating another name.

    This method is one of the ways to use S4U2Self.  It adds credentials
    to the input credentials by impersonating another name using a set of
    proxy credentials.  The impersonator credentials must have a usage of
    'both' or 'initiate'.

    Args:
        input_cred (~gssapi.raw.creds.Creds): the set of credentials to which
            to add the new credentials
        impersonator_cred (~gssapi.raw.creds.Creds): the credentials with
            permissions to impersonate the target name
        name (~gssapi.raw.names.Name): the name to impersonate
        mech (~gssapi.raw.types.MechType): the desired mechanism. Note that
            this is both
            singular and required, unlike acquireCredImpersonateName
        usage (str): the usage type for the credentials: may be
            'initiate', 'accept', or 'both'
        init_lifetime (int): the lifetime, in seconds, for the credentials to
            remain valid when using them to initiate security contexts (or None
            for indefinite)
        accept_lifetime (int): the lifetime, in seconds, for the credentials to
            remain valid when using them to accept security contexts (or None
            for indefinite)

    Returns:
        AddCredResult: the actual mechanisms with which the credentials may be
        used, the actual initiator TTL in seconds, and the actual acceptor TTL
        in seconds (the TTLs may be None for indefinite or not supported)

    Raises:
        ~gssapi.exceptions.GSSError
    """
