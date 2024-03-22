import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.named_tuples import AcquireCredResult
    from gssapi.raw.names import Name
    from gssapi.raw.oids import OID


def acquire_cred_with_password(
    name: "Name",
    password: bytes,
    lifetime: t.Optional[int] = None,
    mechs: t.Optional[t.Iterable["OID"]] = None,
    usage: str = 'initiate',
) -> "AcquireCredResult":
    """Acquire credentials through provided password.

    This function is originally from Solaris and is not documented by either
    MIT or Heimdal.

    In general, it functions similarly to
    :func:`~gssapi.raw.creds.acquire_cred`.

    Args:
        name (~gssapi.raw.names.Name): the name to acquire credentials for
        password (bytes): the password used to acquire credentialss with
        lifetime (int): the lifetime for the credentials in seconds (or None
            for indefinite)
        mechs (~gssapi.raw.types.MechType): the desired mechanisms for which
            the credentials should work (or None for the default set)
        usage (str): usage type for credentials.  Possible values:
            'initiate' (default), 'accept', 'both' (failsafe).

    Returns:
        AcquireCredResult: the resulting credentials, the actual mechanisms
        with which they may be used, and their actual lifetime in seconds (or
        None for indefinite or not supported)

    Raises:
        ~gssapi.exceptions.GSSError
    """
