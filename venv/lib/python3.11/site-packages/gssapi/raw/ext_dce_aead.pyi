import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.named_tuples import WrapResult, UnwrapResult
    from gssapi.raw.sec_contexts import SecurityContext


def wrap_aead(
    context: "SecurityContext",
    message: bytes,
    associated: t.Optional[bytes] = None,
    confidential: bool = True,
    qop: t.Optional[int] = None,
) -> "WrapResult":
    """Wrap/Encrypt an AEAD message.

    This method takes an input message and associated data,
    and outputs and AEAD message.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (bytes): the message to wrap or encrypt
        associated (bytes): associated data to go with the message
        confidential (bool): whether or not to encrypt the message (True),
            or just wrap it with a MIC (False)
        qop (int): the desired Quality of Protection
            (or None for the default QoP)

    Returns:
        WrapResult: the wrapped/encrypted total message, and whether or not
        encryption was actually used

    Raises:
        ~gssapi.exceptions.GSSError
    """


def unwrap_aead(
    context: "SecurityContext",
    message: bytes,
    associated: t.Optional[bytes] = None,
) -> "UnwrapResult":
    """Unwrap/Decrypt an AEAD message.

    This method takes an encrpyted/wrapped AEAD message and some associated
    data, and returns an unwrapped/decrypted message.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (bytes): the AEAD message to unwrap or decrypt
        associated (bytes): associated data that goes with the message

    Returns:
        UnwrapResult: the unwrapped/decrypted message, whether or on
        encryption was used, and the QoP used

    Raises:
        ~gssapi.exceptions.GSSError
    """
