import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.named_tuples import CfxKeyData, Rfc1964KeyData
    from gssapi.raw.sec_contexts import SecurityContext


class Krb5LucidContext:
    """
    The base container returned by :meth:`krb5_export_lucid_sec_context` when
    an unknown version was requested.
    """


class Krb5LucidContextV1(Krb5LucidContext):
    """
    Kerberos context data returned by :meth:`krb5_export_lucid_sec_context`
    when version 1 was requested.
    """

    @property
    def version(self) -> t.Optional[int]:
        """The structure version number

        Returns:
            Optional[int]: the structure version number
        """

    @property
    def is_initiator(self) -> t.Optional[bool]:
        """Whether the context was the initiator

        Returns:
            Optional[bool]: ``True`` when the exported context was the
            initiator
        """

    @property
    def endtime(self) -> t.Optional[int]:
        """Expiration time of the context

        Returns:
            Optional[int]: the expiration time of the context
        """

    @property
    def send_seq(self) -> t.Optional[int]:
        """Sender sequence number

        Returns:
            Optional[int]: the sender sequence number
        """

    @property
    def recv_seq(self) -> t.Optional[int]:
        """Receiver sequence number

        Returns:
            Optional[int]: the receiver sequence number
        """

    @property
    def protocol(self) -> t.Optional[int]:
        """The protocol number

        If the protocol number is 0 then :attr:`rfc1964_kd` is set and
        :attr:`cfx_kd` is `None`. If the protocol number is 1 then the opposite
        is true.

        Protocol 0 refers to RFC1964 and 1 refers to RFC4121.

        Returns:
            Optional[int]: the protocol number
        """

    @property
    def rfc1964_kd(self) -> t.Optional["Rfc1964KeyData"]:
        """Keydata for protocol 0 (RFC1964)

        This will be set when :attr:`protocol` is ``0``.

        Returns:
            Optional[Rfc1964KeyData]: the RFC1964 key data
        """

    @property
    def cfx_kd(self) -> t.Optional["CfxKeyData"]:
        """Key data for protocol 1 (RFC4121)

        This will be set when :attr:`protocol` is ``1``.

        Returns:
            Optional[CfxKeyData]: the RFC4121 key data
        """


def krb5_ccache_name(
    name: t.Optional[bytes],
) -> bytes:
    """Set the default Kerberos Protocol credentials cache name.

    This method sets the default credentials cache name for use by he Kerberos
    mechanism. The default credentials cache is used by
    :meth:`~gssapi.raw.creds.acquire_cred` to create a GSS-API credential. It
    is also used by :meth:`~gssapi.raw.sec_contexts.init_sec_context` when
    `GSS_C_NO_CREDENTIAL` is specified.

    Note:
        Heimdal does not return the old name when called. It also does not
        reset the ccache lookup behaviour when setting to ``None``.

    Note:
        The return value may not be thread safe.

    Args:
        name (Optional[bytes]): the name to set as the new thread specific
            ccache name. Set to ``None`` to revert back to getting the ccache
            from the config/environment settings.

    Returns:
        bytes: the old name that was previously set

    Raises:
        ~gssapi.exceptions.GSSError
    """


def krb5_export_lucid_sec_context(
    context: "SecurityContext",
    version: int,
) -> Krb5LucidContext:
    """Returns a non-opaque version of the internal context info.

    Gets information about the Kerberos security context passed in. Currently
    only version 1 is known and supported by this library.

    Note:
        The context handle must not be used again by the caller after this
        call.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        version (int): the output structure version to export.  Currently
            only 1 is supported.

    Returns:
        Krb5LucidContext: the non-opaque version context info

    Raises:
        ~gssapi.exceptions.GSSError
    """


def krb5_extract_authtime_from_sec_context(
    context: "SecurityContext",
) -> int:
    """Get the auth time for the security context.

    Gets the auth time for the established security context.

    Note:
        Heimdal can only get the authtime on the acceptor security context.
        MIT is able to get the authtime on both initiators and acceptors.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context

    Returns:
        int: the authtime

    Raises:
        ~gssapi.exceptions.GSSError
    """


def krb5_extract_authz_data_from_sec_context(
    context: "SecurityContext",
    ad_type: int,
) -> bytes:
    """Extracts Kerberos authorization data.

    Extracts authorization data that may be stored within the context.

    Note:
        Only operates on acceptor contexts.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        ad_type (int): the type of data to extract

    Returns:
        bytes: the raw authz data from the sec context

    Raises:
        ~gssapi.exceptions.GSSError
    """


def krb5_import_cred(
    cred_handle: "Creds",
    cache: t.Optional[int] = None,
    keytab_principal: t.Optional[int] = None,
    keytab: t.Optional[int] = None,
) -> None:
    """Import Krb5 credentials into GSSAPI credential.

    Imports the krb5 credentials (either or both of the keytab and cache) into
    the GSSAPI credential so it can be used within GSSAPI. The ccache is
    copied by reference and thus shared, so if the credential is destroyed,
    all users of cred_handle will fail.

    Args:
        cred_handle (Creds): the credential handle to import into
        cache (int): the krb5_ccache address pointer, as an int, to import
            from
        keytab_principal (int): the krb5_principal address pointer, as an int,
            of the credential to import
        keytab (int): the krb5_keytab address pointer, as an int, of the
            keytab to import

    Returns:
        None

    Raises:
        ~gssapi.exceptions.GSSError
    """


def krb5_get_tkt_flags(
    context: "SecurityContext",
) -> int:
    """Return ticket flags for the kerberos ticket.

    Return the ticket flags for the kerberos ticket received when
    authenticating the initiator.

    Note:
        Heimdal can only get the tkt flags on the acceptor security context.
        MIT is able to get the tkt flags on initiators and acceptors.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the security
            context

    Returns:
        int: the ticket flags for the received kerberos ticket

    Raises:
        ~gssapi.exceptions.GSSError
    """


def krb5_set_allowable_enctypes(
    cred_handle: "Creds",
    ktypes: t.Iterable[int],
) -> None:
    """Limits the keys that can be exported.

    Called by a context initiator after acquiring the creds but before calling
    :meth:`~gssapi.raw.sec_contexts.init_sec_context` to restrict the set of
    enctypes which will be negotiated during context establisment to those in
    the provided list.

    Warning:
        The cred_handle should not be ``GSS_C_NO_CREDENTIAL``.

    Args:
        cred_hande (Creds): the credential handle
        ktypes (List[int]): list of enctypes allowed

    Returns:
        None

    Raises:
        ~gssapi.exceptions.GSSError
    """
