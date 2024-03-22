import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.ext_dce import IOV
    from gssapi.raw.sec_contexts import SecurityContext


def get_mic_iov(
    context: "SecurityContext",
    message: "IOV",
    qop: t.Optional[int] = None,
) -> None:
    """Generate MIC tokens for the given IOV message.

    This method generates a MIC token for the given IOV message, and places it
    in the :attr:`~gssapi.raw.ext_dce.IOVBufferType.mic_token` buffer in the
    IOV. This method operates entirely in-place, and returns nothing.

    Warning:
        This modifies the input :class:`~gssapi.raw.ext_dce.IOV`.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (IOV): the :class:`~gssapi.raw.ext_dce.IOV` containing the
            message
        qop (int): the desired Quality of Protection
            (or None for the default QoP)

    Returns:
        None

    Raises:
        ~gssapi.exceptions.GSSError
    """


def get_mic_iov_length(
    context: "SecurityContext",
    message: "IOV",
    qop: t.Optional[int] = None,
) -> None:
    """Allocate space for the MIC buffer in the given IOV message.

    This method allocates space for the MIC token buffer
    (:attr:`~gssapi.raw.ext_dce.IOVBufferType.mic_token`) in the given IOV
    message.

    Warning:
        This modifies the input :class:`~gssapi.raw.ext_dce.IOV`.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (IOV): the :class:`~gssapi.raw.ext_dce.IOV` containing the
            message
        qop (int): the desired Quality of Protection
            (or None for the default QoP)

    Returns:
        None

    Raises:
        ~gssapi.exceptions.GSSError
    """


def verify_mic_iov(
    context: "SecurityContext",
    message: "IOV",
    qop: t.Optional[int] = None,
) -> int:
    """Verify that the MIC matches the data in the given IOV message.

    This method verifies that the MIC token in the MIC buffer
    (:attr:`~gssapi.raw.ext_dce.IOVBufferType.mic_token`) match the data
    buffer(s) in the given IOV method.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (IOV): the :class:`~gssapi.raw.ext_dce.IOV` containing the
            message

    Returns:
        int: the QoP used to generate the MIC token

    Raises:
        ~gssapi.exceptions.GSSError
    """
