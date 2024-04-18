import typing as t

from enum import IntEnum

from gssapi.raw.ext_dce_aead import wrap_aead, unwrap_aead

if t.TYPE_CHECKING:
    from gssapi.raw.named_tuples import IOVUnwrapResult, WrapResult
    from gssapi.raw.sec_contexts import SecurityContext


class IOVBufferType(IntEnum):
    """
    IOV Buffer Types

    This IntEnum represent GSSAPI IOV buffer
    types to be used with the IOV methods.

    The numbers behind the values correspond directly
    to their C counterparts.
    """

    empty = 0 #: GSS_IOV_BUFFER_TYPE_EMPTY
    data = 1 #: GSS_IOV_BUFFER_TYPE_DATA
    header = 2 #: GSS_IOV_BUFFER_TYPE_HEADER
    mech_params = 3 #: GSS_IOV_BUFFER_TYPE_MECH_PARAMS
    trailer = 7 #: GSS_IOV_BUFFER_TYPE_TRAILER
    padding = 9 #: GSS_IOV_BUFFER_TYPE_PADDING
    stream = 10 #: GSS_IOV_BUFFER_TYPE_STREAM
    sign_only = 11 #: GSS_IOV_BUFFER_TYPE_SIGN_ONLY
    mic_token = 12 #: GSS_IOV_BUFFER_TYPE_MIC_TOKEN


class IOVBuffer(t.NamedTuple):
    type: IOVBufferType
    allocate: t.Optional[bool]
    value: t.Optional[bytes]


class IOV:
    """A GSSAPI IOV"""

    def __init__(
        self,
        *args: t.Union[
            IOVBuffer,
            t.Tuple[
                t.Union[IOVBufferType, int],
                t.Optional[bool],
                t.Optional[bytes]],
            t.Tuple[
                t.Union[IOVBufferType, int],
                t.Optional[t.Union[bool, bytes]],
            ],
            bytes,
            t.Union[IOVBufferType, int],
        ],
        std_layout: bool = True,
        auto_alloc: bool = True,
    ) -> None: ...

    def __getitem__(
        self,
        ind: int,
    ) -> IOVBuffer: ...

    def __len__(self) -> int: ...

    def __iter__(self) -> t.Iterator[IOVBuffer]: ...

    def __contains__(
        self,
        item: IOVBuffer,
    ) -> bool: ...

    def __reversed__(self) -> t.Iterator[IOVBuffer]: ...

    def index(
        self,
        value: t.Any,
    ) -> int: ...

    def count(
        self,
        value: t.Any,
    ) -> int: ...


def wrap_iov(
    context: "SecurityContext",
    message: IOV,
    confidential: bool = True,
    qop: t.Optional[int] = None,
) -> bool:
    """Wrap/Encrypt an IOV message.

    This method wraps or encrypts an IOV message.  The allocate
    parameter of the :class:`IOVBuffer` objects in the :class:`IOV`
    indicates whether or not that particular buffer should be
    automatically allocated (for use with padding, header, and
    trailer buffers).

    Warning:
        This modifies the input :class:`IOV`.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (IOV): an :class:`IOV` containing the message
        confidential (bool): whether or not to encrypt the miovessage (True),
            or just wrap it with a MIC (False)
        qop (int): the desired Quality of Protection
            (or None for the default QoP)

    Returns:
        bool: whether or not confidentiality was actually used

    Raises:
        ~gssapi.exceptions.GSSError
    """


def unwrap_iov(
    context: "SecurityContext",
    message: IOV,
) -> "IOVUnwrapResult":
    """Unwrap/Decrypt an IOV message.

    This method uwraps or decrypts an IOV message.  The allocate
    parameter of the :class:`IOVBuffer` objects in the :class:`IOV`
    indicates whether or not that particular buffer should be
    automatically allocated (for use with padding, header, and
    trailer buffers).

    As a special case, you may pass an entire IOV message
    as a single 'stream'.  In this case, pass a buffer type
    of :attr:`IOVBufferType.stream` followed by a buffer type of
    :attr:`IOVBufferType.data`.  The former should contain the
    entire IOV message, while the latter should be empty.

    Warning:
        This modifies the input :class:`IOV`.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (IOV): an :class:`IOV` containing the message

    Returns:
        IOVUnwrapResult: whether or not confidentiality was used,
        and the QoP used.

    Raises:
        ~gssapi.exceptions.GSSError
    """


def wrap_iov_length(
    context: "SecurityContext",
    message: IOV,
    confidential: bool = True,
    qop: t.Optional[int] = None,
) -> "WrapResult":
    """Appropriately size padding, trailer, and header IOV buffers.

    This method sets the length values on the IOV buffers.  You
    should already have data provided for the data (and sign-only)
    buffer(s) so that padding lengths can be appropriately computed.

    In Python terms, this will result in an appropriately sized
    `bytes` object consisting of all zeros.

    Warning:
        This modifies the input :class:`IOV`.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the current
            security context
        message (IOV): an :class:`IOV` containing the message

    Returns:
        WrapResult: a list of :class:IOVBuffer` objects, and whether or not
        encryption was actually used

    Raises:
        ~gssapi.exceptions.GSSError
    """
