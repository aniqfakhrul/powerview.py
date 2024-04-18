"""
gss_set_cred_option

Provides a way to set options on a credential based on the OID specified. A
common use case is to set the GSS_KRB5_CRED_NO_CI_FLAGS_X on a Kerberos
credential. This is used for interoperability with Microsoft's SSPI.

Note this function is commonly lumped with the GGF extensions but they are not
part of the GGF IETF draft so it's separated into it's own file.

Closest draft IETF document for the gss_set_cred_option can be found at
https://tools.ietf.org/html/draft-williams-kitten-channel-bound-flag-01
"""
import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.oids import OID


def set_cred_option(
    desired_aspect: "OID",
    creds: t.Optional["Creds"] = None,
    value: t.Optional[bytes] = None,
) -> "Creds":
    """
    This method is used to set options of a :class:`~gssapi.raw.creds.Creds`
    object based on an OID key. The options that can be set depends on the mech
    the credentials were created with.

    An example of how this can be used would be to set the
    GSS_KRB5_CRED_NO_CI_FLAGS_X on a Kerberos credential. The OID string for
    this flag is '1.2.752.43.13.29' and it requires no value to be set. This
    must be set before the SecurityContext was initialised with the
    credentials.

    Args:
        desired_aspect (~gssapi.raw.oids.OID): the desired aspect of the
            Credential to set.
        cred_handle (~gssapi.raw.creds.Creds): the Credentials to set, or None
            to create a new credential.
        value (bytes): the value to set on the desired aspect of the Credential
            or None to send GSS_C_EMPTY_BUFFER.

    Returns:
        Creds: The output credential.

    Raises:
        ~gssapi.exceptions.GSSError
    """
