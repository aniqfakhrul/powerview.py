import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.named_tuples import WrapResult, UnwrapResult
    from gssapi.sec_contexts import SecurityContext


def get_mic(
    context: "SecurityContext",
    message: bytes,
    qop: t.Optional[int] = None,
) -> bytes:
    """Generate a MIC for a message.

    This method generates a Message Integrity Check token for the
    given message.  This can be separately trasmitted to the other
    entity, unlike wrap, which bundles the MIC and the message
    together.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (bytes): the message for which to generate the MIC
        qop (int): the requested Quality of Protection
            (or None to use the default)

    Returns:
        bytes: the generated MIC token

    Raises:
        ~gssapi.exceptions.ExpiredContextError
        ~gssapi.exceptions.MissingContextError
        ~gssapi.exceptions.BadQoPError
    """


def verify_mic(
    context: "SecurityContext",
    message: bytes,
    token: bytes,
) -> int:
    """Verify that a MIC matches a message.

    This method verifies that the given MIC matches the given message.
    If the MIC does not match the given message, an exception will
    be raised.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (bytes): the message in question
        token (bytes): the MIC token in question

    Returns:
        int: the QoP used.

    Raises:
        ~gssapi.exceptions.InvalidTokenError
        ~gssapi.exceptions.BadMICError
        ~gssapi.exceptions.DuplicateTokenError
        ~gssapi.exceptions.ExpiredTokenError
        ~gssapi.exceptions.TokenTooLateError
        ~gssapi.exceptions.TokenTooEarlyError
        ~gssapi.exceptions.ExpiredContextError
        ~gssapi.exceptions.MissingContextError
    """


def wrap_size_limit(
    context: "SecurityContext",
    output_size: int,
    confidential: bool = True,
    qop: t.Optional[int] = None,
) -> int:
    """Calculate the max message size.

    This method calculates the unwrapped/unencrypted message size for
    the given maximum wrapped/encrypted message size.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        output_size (int): the maximum desired wrapped/encrypted message size
        confidential (bool): whether or not confidentiality is being used
        qop (int): the QoP that will be when you actually call wrap
            (or None for the default QoP)

    Returns:
        int: the maximum unencrypted/unwrapped message size

    Raises:
        ~gssapi.exceptions.MissingContextError
        ~gssapi.exceptions.ExpiredContextError
        ~gssapi.exceptions.BadQoPError
    """


def wrap(
    context: "SecurityContext",
    message: bytes,
    confidential: bool = True,
    qop: t.Optional[int] = None,
) -> "WrapResult":
    """Wrap/Encrypt a message.

    This method wraps or encrypts a message (depending on the value
    of confidential) with the given Quality of Protection.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (bytes): the message to wrap or encrypt
        confidential (bool): whether or not to encrypt the message (True),
            or just wrap it with a MIC (False)
        qop (int): the desired Quality of Protection
            (or None for the default QoP)

    Returns:
        WrapResult: the wrapped/encrypted message, and whether or not
            encryption was actually used

    Raises:
        ~gssapi.exceptions.ExpiredContextError
        ~gssapi.exceptions.MissingContextError
        ~gssapi.exceptions.BadQoPError
    """


def unwrap(
    context: "SecurityContext",
    message: bytes,
) -> "UnwrapResult":
    """Unwrap/Decrypt a message.

    This method unwraps or decrypts a message, depending
    on whether the sender used confidentiality.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (bytes): the message to unwrap/decrypt

    Returns:
        UnwrapResult: the unwrapped/decrypted message, whether or on
            encryption was used, and the QoP used

    Raises:
        ~gssapi.exceptions.InvalidTokenError
        ~gssapi.exceptions.BadMICError
        ~gssapi.exceptions.DuplicateTokenError
        ~gssapi.exceptions.ExpiredTokenError
        ~gssapi.exceptions.TokenTooLateError
        ~gssapi.exceptions.TokenTooEarlyError
        ~gssapi.exceptions.ExpiredContextError
        ~gssapi.exceptions.MissingContextError
    """
