import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.named_tuples import StoreCredResult
    from gssapi.raw.oids import OID


def store_cred(
    creds: "Creds",
    usage: str = 'both',
    mech: t.Optional["OID"] = None,
    overwrite: bool = False,
    set_default: bool = False,
) -> "StoreCredResult":
    """Store credentials into the default store.

    This method stores the given credentials into the default store.
    They may then be retrieved later using
    :func:`~gssapi.raw.creds.acquire_cred`.

    Args:
        creds (Creds): the credentials to store
        usage (str): the usage to store the credentials with -- either
            'both', 'initiate', or 'accept'
        mech (~gssapi.OID): the mechansim to associate with the stored
            credentials
        overwrite (bool): whether or not to overwrite existing credentials
            stored with the same name, etc
        set_default (bool): whether or not to set these credentials as
            the default credentials for the given store.

    Returns:
        StoreCredResult: the results of the credential storing operation

    Raises:
        ~gssapi.exceptions.GSSError
        ~gssapi.exceptions.ExpiredCredentialsError
        ~gssapi.exceptions.MissingCredentialsError
        ~gssapi.exceptions.OperationUnavailableError
        ~gssapi.exceptions.DuplicateCredentialsElementError
    """
