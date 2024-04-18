import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.oids import OID


def set_neg_mechs(
    cred_handle: "Creds",
    mech_set: t.Iterable["OID"],
) -> None:
    """
    Specify the set of security mechanisms that may be negotiated with
    the credential identified by cred_handle.
    If more than one mechanism is specified in mech_set, the order in
    which those mechanisms are specified implies a relative preference.

    Args:
        cred_handle (Creds): credentials to set negotiable mechanisms for
        mech_set (~gssapi.raw.types.MechType): negotiable mechanisms to be set

    Returns:
        None

    Raises:
        ~gssapi.exceptions.GSSError
    """
