"""Credential Store Extension"""
import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.named_tuples import AcquireCredResult, StoreCredResult
    from gssapi.raw.names import Name
    from gssapi.raw.oids import OID


def acquire_cred_from(
    dict_store: t.Optional[
        t.Dict[t.Union[bytes, str], t.Union[bytes, str]]
    ] = None,
    name: t.Optional["Name"] = None,
    lifetime: t.Optional[int] = None,
    mechs: t.Optional[t.Iterable["OID"]] = None,
    usage: str = 'both',
) -> "AcquireCredResult":
    """Acquire credentials from the given store.

    This method acquires credentials from the store specified by the
    given credential store information.

    The credential store information is a dictionary containing
    mechanisms-specific keys and values pointing to a credential store
    or stores.

    Args:
        store (dict): the credential store information pointing to the
            credential store from which to acquire the credentials.
            See :doc:`credstore` for valid values
        name (~gssapi.raw.names.Name): the name associated with the
            credentials, or None for the default name
        lifetime (int): the desired lifetime of the credentials in seconds, or
            None for indefinite
        mechs (list): the desired mechanisms to be used with these
            credentials, or None for the default set
        usage (str): the usage for these credentials -- either 'both',
            'initiate', or 'accept'

    Returns:
        AcquireCredResult: the acquired credentials and information about
        them

    Raises:
        ~gssapi.exceptions.GSSError
    """


def add_cred_from(
    dict_store: t.Optional[
        t.Dict[t.Union[bytes, str], t.Union[bytes, str]]
    ],
    input_creds: "Creds",
    name: "Name",
    mech: "OID",
    usage: str = 'both',
    init_lifetime: t.Optional[int] = None,
    accept_lifetime: t.Optional[int] = None,
) -> "AcquireCredResult":
    """Acquire credentials to add to the current set from the given store.

    This method works like :func:`acquire_cred_from`, except that it
    adds the acquired credentials for a single mechanism to a copy of
    the current set, instead of creating a new set for multiple mechanisms.
    Unlike :func:`~gssapi.raw.creds.acquire_cred`, you cannot pass None for the
    desired name or mechanism.

    The credential store information is a dictionary containing
    mechanisms-specific keys and values pointing to a credential store
    or stores.

    Args:
        store (dict): the store into which to store the credentials,
            or None for the default store.
            See :doc:`credstore` for valid values
        name (~gssapi.raw.names.Name): the name associated with the credentials
        mech (~gssapi.OID): the desired mechanism to be used with these
            credentials
        usage (str): the usage for these credentials -- either 'both',
            'initiate', or 'accept'
        init_lifetime (int): the desired initiate lifetime of the credentials
            in seconds, or None for indefinite
        accept_lifetime (int): the desired accept lifetime of the credentials
            in seconds, or None for indefinite

    Returns:
        AcquireCredResult: the new credentials set and information about
        it

    Raises:
        ~gssapi.exceptions.GSSError
    """


def store_cred_into(
    dict_store: t.Optional[
        t.Dict[t.Union[bytes, str], t.Union[bytes, str]]
    ],
    creds: "Creds",
    usage: str = 'both',
    mech: t.Optional["OID"] = None,
    overwrite: bool = False,
    set_default: bool = False,
) -> "StoreCredResult":
    """Store credentials into the given store.

    This method stores the given credentials into the store specified
    by the given store information.  They may then be retrieved later using
    :func:`acquire_cred_from` or :func:`add_cred_from`.

    The credential store information is a dictionary containing
    mechanisms-specific keys and values pointing to a credential store
    or stores.

    Args:
        store (dict): the store into which to store the credentials,
            or None for the default store.
            See :doc:`credstore` for valid values
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
    """
