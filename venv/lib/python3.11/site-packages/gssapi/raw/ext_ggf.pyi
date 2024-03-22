"""
GGF Extensions

GGF provides extended credential and security context inquiry that allows
application to retrieve more information about the client's credentials and
security context. One common use case is to use
:meth:`inquire_sec_context_by_oid` to retrieve the "session" key that is
required by the SMB protocol for signing and encrypting a message.

Draft IETF document for these extensions can be found at
https://tools.ietf.org/html/draft-engert-ggf-gss-extensions-00
"""
import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds
    from gssapi.raw.oids import OID
    from gssapi.raw.sec_contexts import SecurityContext


def inquire_cred_by_oid(
    cred_handle: "Creds",
    desired_aspect: "OID",
) -> t.List[bytes]:
    """
    This method inspects a :class:`~gssapi.raw.creds.Creds` object for
    information specific to a particular desired aspect as an OID.

    Args:
        cred_handle (Creds): the Credentials to query
        desired_aspect (~gssapi.raw.oids.OID): the desired aspect of the
            Credentials to inquire about.

    Returns:
        list: A list of zero or more pieces of data (as bytes objects)

    Raises:
        ~gssapi.exceptions.GSSError
    """


def inquire_sec_context_by_oid(
    context: "SecurityContext",
    desired_aspect: "OID",
) -> t.List[bytes]:
    """
    This method inspects a :class:`~gssapi.raw.sec_contexts.SecurityContext`
    object for information specific to a particular desired aspect as an OID.

    This method can be used with the GSS_KRB5_INQ_SSPI_SESSION_KEY_OID OID to
    retrieve the required key that is used to derive the SMB/SAMBA signing and
    encryption keys.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the Security
            Context to query
        desired_aspect (~gssapi.raw.oids.OID): the desired aspect of the
            Security Context to inquire about.

    Returns:
        list: A list of zero or more pieces of data (as bytes objects)

    Raises:
        ~gssapi.exceptions.GSSError
    """


def set_sec_context_option(
    desired_aspect: "OID",
    context: "SecurityContext",
    value: t.Optional[bytes] = None,
) -> None:
    """
    This method is used to set a value for a specific OID of a
    :class:`~gssapi.raw.sec_contexts.SecurityContext` object. The OID and value
    to pass in depends on the mech the SecurityContext backs.

    An example of how this can be used would be to reset the NTLM crypto engine
    used in gss-ntlmssp. The OID that controls this value is
    '1.3.6.1.4.1.7165.655.1.3' and it takes it a byte value that represents
    an int32 where 1 resets the verifier handle and any other int resets the
    sender handle.

    Args:
        desired_aspect (~gssapi.raw.oids.OID): the desired aspect of the
            Security Context to set the value for.
        context (~gssapi.raw.sec_contexts.SecurityContext): the Security
            Context to set, or None to create a new context.
        value (bytes): the value to set on the desired aspect of the Security
            Context or None to send GSS_C_EMPTY_BUFFER.

    Returns:
        ~gssapi.raw.sec_contexts.SecurityContext: The output security context.

    Raises:
        ~gssapi.exceptions.GSSError
    """
