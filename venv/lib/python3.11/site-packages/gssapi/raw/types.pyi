import numbers
import typing as t

from collections.abc import MutableSet
from enum import IntEnum

if t.TYPE_CHECKING:
    from gssapi.raw.oids import OID


class NameType:
    """
    GSSAPI Name Types

    This enum-like object represents GSSAPI name
    types (to be used with :func:`~gssapi.raw.names.import_name`, etc)
    """
    #: GSS_C_NT_ANONYMOUS 1.3.6.1.5.6.3
    anonymous: "OID" = ...
    #: GSS_C_NT_EXPORT_NAME 1.3.6.1.5.6.4
    export: "OID" = ...
    #: GSS_C_NT_HOSTBASED_SERVICE 1.2.840.113554.1.2.1.4
    hostbased_service: "OID" = ...
    #: GSS_C_NT_MACHINE_UID_NAME 1.2.840.113554.1.2.1.2
    machine_uid: "OID" = ...
    #: GSS_C_NT_STRING_UID_NAME 1.2.840.113554.1.2.1.3
    string_uid: "OID" = ...
    #: GSS_C_NT_USER_NAME 1.2.840.113554.1.2.1.1
    user: "OID" = ...

    # Provided through optional extensions
    #: GSS_C_NT_COMPOSITE_EXPORT 1.3.6.1.5.6.6
    composite_export: "OID" = ...
    #: GSS_KRB5_NT_PRINCIPAL_NAME 1.2.840.113554.1.2.2.1
    kerberos_principal: "OID" = ...
    #: GSS_KRB5_NT_PRINCIPAL_NAME 1.2.840.113554.1.2.2.1
    krb5_nt_principal_name: "OID" = ...


class RequirementFlag(IntEnum):
    """
    GSSAPI Requirement Flags

    This :class:`~enum.IntEnum` represents flags used with the
    :class:`~gssapi.raw.sec_contexts.SecurityContext`-related methods (e.g.
    :func:`~gssapi.raw.sec_contexts.init_sec_context`)

    The numbers behind the values correspond directly
    to their C counterparts.
    """
    # Note the values are only set here for documentation and type hints
    delegate_to_peer = 1 #: GSS_C_DELEG_FLAG
    mutual_authentication = 2 #: GSS_C_MUTUAL_FLAG
    replay_detection = 4 #: GSS_C_REPLAY_FLAG
    out_of_sequence_detection = 8 #: GSS_C_SEQUENCE_FLAG
    confidentiality = 16 #: GSS_C_CONF_FLAG
    integrity = 32 #: GSS_C_INTEG_FLAG
    anonymity = 64 #: GSS_C_ANON_FLAG
    protection_ready = 128 #: GSS_C_PROT_READY_FLAG
    transferable = 256 #: GSS_C_TRANS_FLAG
    channel_bound = 2048 #: GSS_C_CHANNEL_BOUND_FLAG
    dce_style = 4096 #: GSS_C_DCE_STYLE
    identify = 8192 #: GSS_C_IDENTIFY_FLAG
    extended_error = 16384 #: GSS_C_EXTENDED_ERROR_FLAG
    ok_as_delegate = 32768 #: GSS_C_DELEG_POLICY_FLAG


class AddressType(IntEnum):
    """
    GSSAPI Channel Bindings Address Types

    This :class:`~enum.IntEnum` represents the various address
    types used with the :class:`~gssapi.raw.chan_bindings.ChannelBindings`
    structure.

    The numbers behind the values correspond directly
    to their C counterparts.  There is no value for
    ``GSS_C_AF_UNSPEC``, since this is represented
    by ``None``.
    """
    # Note the values are only set here for documentation and type hints
    local = 1 #: GSS_C_AF_LOCAL
    ip = 2 #: GSS_C_AF_INET
    arpanet = 3 #: GSS_C_AF_IMPLINK
    pup = 4 #: GSS_C_AF_PUP
    chaos = 5 #: GSS_C_AF_CHAOS
    xerox_ns = 6 #: GSS_C_AF_NS
    nbs = 7 #: GSS_C_AF_NBS
    ecma = 8 #: GSS_C_AF_ECMA
    datakit = 9 #: GSS_C_AF_DATAKIT
    ccitt = 10 #: GSS_C_AF_CCITT
    ibm_sna = 11 #: GSS_C_AF_SNA
    decnet = 12 #: GSS_C_AF_DECnet
    dli = 13 #: GSS_C_AF_DLI
    lat = 14 #: GSS_C_AF_LAT
    hyperchannel = 15 #: GSS_C_AF_HYLINK
    appletalk = 16 #: GSS_C_AF_APPLETALK
    bisync = 17 #: GSS_C_AF_BSC
    dss = 18 #: GSS_C_AF_DSS
    osi_tp4 = 19 #: GSS_C_AF_OSI
    x25 = 21 #: GSS_C_AF_X25
    null = 255 #: GSS_C_AF_NULLADDR


class MechType:
    """
    GSSAPI Mechanism Types

    This enum-like object contains any mechanism :class:`~gssapi.raw.oids.OID`
    values registered by imported mechanisms.
    """
    kerberos: "OID" #: gss_mech_krb5 1.2.840.113554.1.2.2


class GenericFlagSet(MutableSet):
    """A set backed by a 32-bit integer

    This is a set backed by a 32 bit integer.
    the members are integers where only one
    bit is set.

    The class supports normal set operations,
    as well as traditional "flag set" operations,
    such as bitwise AND, OR, and XOR.
    """

    MAX_VAL: int

    def __init__(
        self,
        flags: t.Optional[
            t.Union[GenericFlagSet, numbers.Integral, int]
        ] = None,
    ) -> None: ...

    def __contains__(
        self,
        flag: object,
    ) -> bool: ...

    def __iter__(self) -> t.Iterator[int]: ...

    def __len__(self) -> int: ...

    def add(
        self,
        flag: int,
    ) -> None: ...

    def discard(
        self,
        flag: int,
    ) -> None: ...


class IntEnumFlagSet(GenericFlagSet):
    """A set backed by a 32-bit integer with enum members

    This class is a :class:`GenericFlagSet` where the returned
    members are values in an :class:`~enum.IntEnum`.

    It functions exactly like a `GenericFlagSet`, except that
    it also supports bitwise operations with the enum values.
    """

    def __init__(
        self,
        enum: t.Type[IntEnum],
        flags: t.Optional[
            t.Union[GenericFlagSet, numbers.Integral, int]
        ] = None,
    ) -> None: ...

    def __iter__(self) -> t.Iterator[IntEnum]: ...
