import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.names import Name
    from gssapi.raw.oids import OID
    from gssapi.raw.named_tuples import (
        AcquireCredResult,
        AddCredResult,
        InquireCredResult,
        InquireCredByMechResult,
    )


class Creds:
    """
    GSSAPI Credentials
    """

    def __new__(
        cls,
        cpy: t.Optional["Creds"] = None,
    ) -> "Creds": ...


def acquire_cred(
    name: t.Optional["Name"],
    lifetime: t.Optional[int] = None,
    mechs: t.Optional[t.Iterable["OID"]] = None,
    usage: str = 'both',
) -> "AcquireCredResult":
    """Get GSSAPI credentials for the given name and mechanisms.

    This method gets GSSAPI credentials corresponding to the given name
    and mechanims.  The desired TTL and usage for the the credential may also
    be specified.

    Args:
        name (~gssapi.raw.names.Name): the name for which to acquire the
            credentials (or None for the "no name" functionality)
        lifetime (int): the lifetime in seconds for the credentials (or None
            for indefinite)
        mechs (~gssapi.raw.types.MechType): the desired mechanisms for which
            the credentials should work, or None for the default set
        usage (str): the usage type for the credentials: may be
            'initiate', 'accept', or 'both'

    Returns:
        AcquireCredResult: the resulting credentials, the actual mechanisms
        with which they may be used, and their actual lifetime in seconds (or
        None for indefinite or not supported)

    Raises:
        ~gssapi.exceptions.BadMechanismError
        ~gssapi.exceptions.BadNameTypeError
        ~gssapi.exceptions.BadNameError
        ~gssapi.exceptions.ExpiredCredentialsError
        ~gssapi.exceptions.MissingCredentialsError
    """


def release_cred(
    creds: Creds,
) -> None:
    """
    release_cred(creds)
    Release GSSAPI Credentials.

    This method releases GSSAPI credentials.

    Warning:
        This method is deprecated.  Credentials are
        automatically freed by Python.

    Args:
        creds (Creds): the credentials in question

    Raises:
        ~gssapi.exceptions.MissingCredentialsError
    """


def add_cred(
    input_cred: Creds,
    name: "Name",
    mech: "OID",
    usage: str = 'initiate',
    init_lifetime: t.Optional[int] = None,
    accept_lifetime: t.Optional[int] = None,
    mutate_input: bool = False,
) -> "AddCredResult":
    """Add a credential element to a credential.

    This method can be used to either compose two credentials (i.e., original
    and new credential), or to add a new element to an existing credential.

    Args:
        input_cred (Creds): the set of credentials to which to add the new
            credentials
        name (~gssapi.raw.names.Name): name of principal to acquire a
            credential for
        mech (~gssapi.raw.types.MechType): the desired security mechanism
            (required).
        usage (str): usage type for credentials.  Possible values:
            'initiate' (default), 'accept', 'both' (failsafe).
        init_lifetime (int): lifetime of credentials for use in initiating
            security contexts in seconds (None for indefinite)
        accept_lifetime (int): lifetime of credentials for use in accepting
            security contexts in seconds (None for indefinite)
        mutate_input (bool): whether to mutate the input credentials (True)
            or produce a new set of credentials (False).  Defaults to False

    Returns:
        AddCredResult: the actual mechanisms with which the credentials may be
        used, the actual initiator TTL, and the actual acceptor TTL (None for
        either indefinite or not supported).  Note that the credentials may
        be set to None if mutate_input is set to True.

    Raises:
        ~gssapi.exceptions.BadMechanismError
        ~gssapi.exceptions.BadNameTypeError
        ~gssapi.exceptions.BadNameError
        ~gssapi.exceptions.DuplicateCredentialsElementError
        ~gssapi.exceptions.ExpiredCredentialsError
        ~gssapi.exceptions.MissingCredentialsError
    """


def inquire_cred(
    creds: Creds,
    name: bool = True,
    lifetime: bool = True,
    usage: bool = True,
    mechs: bool = True,
) -> "InquireCredResult":
    """Inspect credentials for information.

    This method inspects a :class:`Creds` object for information.

    Args:
        creds (Creds): the credentials to inspect
        name (bool): get the Name associated with the credentials
        lifetime (bool): get the TTL for the credentials
        usage (bool): get the usage type of the credentials
        mechs (bool): the mechanims used with the credentials

    Returns:
        InquireCredResult: the information about the credentials,
        with unused fields set to None

    Raises:
        ~gssapi.exceptions.MissingCredentialsError
        ~gssapi.exceptions.InvalidCredentialsError
        ~gssapi.exceptions.ExpiredCredentialsError
    """


def inquire_cred_by_mech(
    creds: Creds,
    mech: "OID",
    name: bool = True,
    init_lifetime: bool = True,
    accept_lifetime: bool = True,
    usage: bool = True,
) -> "InquireCredByMechResult":
    """Inspect credentials for mechanism-specific information.

    This method inspects a :class:`Creds` object for information
    specific to a particular mechanism.  It functions similarly
    to :func:`inquire_cred`.

    Args:
        creds (Creds): the credentials to inspect
        mech (~gssapi.OID): the desired mechanism
        name (bool): get the Name associated with the credentials
        init_lifetime (bool): get the initiator TTL for the credentials (in
            seconds)
        accept_lifetime (bool): get the acceptor TTL for the credentials (in
            seconds)
        usage (bool): get the usage type of the credentials

    Returns:
        InquireCredByMechResult: the information about the credentials,
        with unused fields set to None

    Raises:
        ~gssapi.exceptions.MissingCredentialsError
        ~gssapi.exceptions.InvalidCredentialsError
    """
