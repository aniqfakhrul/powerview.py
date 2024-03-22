from typing import List, NamedTuple, Optional, Set, TYPE_CHECKING

from gssapi.raw.oids import OID
from gssapi.raw.types import RequirementFlag

if TYPE_CHECKING:
    import gssapi


class AcquireCredResult(NamedTuple):
    """Credential result when acquiring a GSSAPI credential."""
    #: GSSAPI credentials that were acquired
    creds: "gssapi.raw.creds.Creds"
    #: Set of mechs the cred is for
    mechs: Set[OID]
    #: Number of seconds for which the cred will remain valid
    lifetime: int


class InquireCredResult(NamedTuple):
    """Information about the credential."""
    #: The principal associated with the credential
    name: Optional["gssapi.raw.names.Name"]
    #: Number of seconds which the cred is valid for
    lifetime: Optional[int]
    #: How the credential can be used
    usage: Optional[str]
    #: Set of mechs the cred is for
    mechs: Optional[Set[OID]]


class InquireCredByMechResult(NamedTuple):
    """Information about the credential for a specific mechanism."""
    #: The principal associated with the credential
    name: Optional["gssapi.raw.names.Name"]
    #: Time valid for initiation, in seconds
    init_lifetime: Optional[int]
    #: Time valid for accepting, in seconds
    accept_lifetime: Optional[int]
    #: How the credential can be used
    usage: Optional[str]


class AddCredResult(NamedTuple):
    """Result of adding to a GSSAPI credential."""
    #: The credential that was generated
    creds: Optional["gssapi.raw.creds.Creds"]
    #: Set of mechs the cred is for
    mechs: Set[OID]
    #: Time valid for initiation, in seconds
    init_lifetime: int
    #: Time valid for accepting, in seconds
    accept_lifetime: int


class DisplayNameResult(NamedTuple):
    """Textual representation of a GSSAPI name."""
    #: The representation of the GSSAPI name
    name: bytes
    #: The type of GSSAPI name
    name_type: Optional[OID]


class WrapResult(NamedTuple):
    """Wrapped message result."""
    #: The wrapped message
    message: bytes
    #: Whether the message is encrypted and not just signed
    encrypted: bool


class UnwrapResult(NamedTuple):
    """Unwrapped message result."""
    #: The unwrapped message
    message: bytes
    #: Whether the message was encrypted and not just signed
    encrypted: bool
    #: The quality of protection applied to the message
    qop: int


class AcceptSecContextResult(NamedTuple):
    """Result when accepting a security context by an initiator."""
    #: The acceptor security context
    context: "gssapi.raw.sec_contexts.SecurityContext"
    #: The authenticated name of the initiator
    initiator_name: "gssapi.raw.names.Name"
    #: Mechanism with which the context was established
    mech: OID
    #: Token to be returned to the initiator
    token: Optional[bytes]
    #: Services requested by the initiator
    flags: RequirementFlag
    #: Seconds for which the context is valid for
    lifetime: int
    #: Delegated credentials
    delegated_creds: Optional["gssapi.raw.creds.Creds"]
    #: More input is required to complete the exchange
    more_steps: bool


class InitSecContextResult(NamedTuple):
    """Result when initiating a security context"""
    #: The initiator security context
    context: "gssapi.raw.sec_contexts.SecurityContext"
    #: Mechanism used in the security context
    mech: OID
    #: Services available for the context
    flags: RequirementFlag
    #: Token to be sent to the acceptor
    token: Optional[bytes]
    #: Seconds for which the context is valid for
    lifetime: int
    #: More input is required to complete the exchange
    more_steps: bool


class InquireContextResult(NamedTuple):
    """Information about the security context."""
    #: Name of the initiator
    initiator_name: Optional["gssapi.raw.names.Name"]
    #: Name of the acceptor
    target_name: Optional["gssapi.raw.names.Name"]
    #: Time valid for the security context, in seconds
    lifetime: Optional[int]
    #: Mech used to create the security context
    mech: Optional[OID]
    #: Services available for the context
    flags: Optional[RequirementFlag]
    #: Context was initiated locally
    locally_init: Optional[bool]
    #: Context has been established and ready to use
    complete: Optional[bool]


class StoreCredResult(NamedTuple):
    """Result of the credential storing operation."""
    #: Mechs that were stored in the credential store
    mechs: List[OID]
    #: How the credential can be used
    usage: str


class IOVUnwrapResult(NamedTuple):
    """Unwrapped IOV message result."""
    #: Whether the message was encrypted and not just signed
    encrypted: bool
    #: The quality of protection applied to the message
    qop: int


class InquireNameResult(NamedTuple):
    """Information about a GSSAPI Name."""
    #: Set of attribute names
    attrs: List[bytes]
    #: Name is a mechanism name
    is_mech_name: bool
    #: The mechanism if is_name_mech is True
    mech: OID


class GetNameAttributeResult(NamedTuple):
    """GSSAPI Name attribute values."""
    #: Raw values
    values: List[bytes]
    #: Human-readable values
    display_values: List[bytes]
    #: Attribute has been authenticated
    authenticated: bool
    #: Attribute value is marked as complete
    complete: bool


class InquireAttrsResult(NamedTuple):
    """Set of attributes supported and known by a mechanism."""
    #: The mechanisms attributes
    mech_attrs: Set[OID]
    #: Known attributes of the mechanism
    known_mech_attrs: Set[OID]


class DisplayAttrResult(NamedTuple):
    """Information about an attribute."""
    #: The mechanism name
    name: bytes
    #: Short description of the mechanism
    short_desc: bytes
    #: Long description of the mechanism
    long_desc: bytes


class InquireSASLNameResult(NamedTuple):
    """SASL informmation about a GSSAPI Name."""
    #: The SASL name
    sasl_mech_name: bytes
    #: The mechanism name
    mech_name: bytes
    #: The mechanism description
    mech_description: bytes


class Rfc1964KeyData(NamedTuple):
    """Security context key data based on RFC1964."""
    #: Signing algorithm identifier
    sign_alg: int
    #: Sealing algorithm identifier
    seal_alg: int
    #: Key encryption type identifier
    key_type: int
    #: Encryption key data
    key: bytes


class CfxKeyData(NamedTuple):
    """Securty context key data."""
    #: Context key encryption type identifier
    ctx_key_type: int
    #: Context key data - session or sub-session key
    ctx_key: bytes
    #: Acceptor key enc type identifier
    acceptor_subkey_type: Optional[int]
    #: Acceptor key data
    acceptor_subkey: Optional[bytes]
