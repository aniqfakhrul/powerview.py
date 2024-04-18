import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.named_tuples import InquireSASLNameResult
    from gssapi.raw.oids import OID


def inquire_saslname_for_mech(
    mech: "OID",
) -> "InquireSASLNameResult":
    """Gets information about a specified mech, including the SASL name,
    the mech name, and the mech description.

    Args:
        mech (~gssapi.OID): Mechanism to inquire about

    Returns:
        InquireSASLNameResult: the results of inquiry; a mech's SASL name,
        name, and description.

    Raises:
        ~gssapi.exceptions.GSSError: an unknown failure occurred
    """


def inquire_mech_for_saslname(
    sasl_name: bytes,
) -> "OID":
    """Gets the OID for the mech specified by SASL name.

    Args:
        sasl_name (bytes): SASL name of the mechanism

    Returns:
        ~gssapi.OID: the mechanism with corresponding SASL name.

    Raises:
        ~gssapi.exceptions.GSSError: An unknown failure occurred
    """
