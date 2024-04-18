import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.named_tuples import AddCredResult
    from gssapi.raw.names import Name
    from gssapi.raw.oids import OID


def add_cred_with_password(
    input_cred: "Creds",
    name: "Name",
    mech: "OID",
    password: bytes,
    usage: str = 'initiate',
    init_lifetime: t.Optional[int] = None,
    accept_lifetime: t.Optional[int] = None,
) -> "AddCredResult":
    """Add a credential-element to a credential using provided password.

    This function is originally from Solaris and is not documented by either
    MIT or Heimdal.

    In general, it functions similarly to :func:`~gssapi.raw.creds.add_cred`.

    Args:
        input_cred (~gssapi.raw.creds.Creds): the credentials to add to
        name (~gssapi.raw.names.Name): the name to acquire credentials for
        mech (~gssapi.raw.types.MechType): the desired mechanism.  Note that
            this is both singular and required
        password (bytes): the password used to acquire credentialss with
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
