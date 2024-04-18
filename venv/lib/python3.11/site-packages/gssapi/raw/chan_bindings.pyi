import typing as t


class ChannelBindings:
    """GSSAPI Channel Bindings

    This class represents a set of GSSAPI channel bindings.

    Args:
        initiator_address_type: the initiator address type
        initiator_address: the initiator address
        acceptor_address_type:  the acceptor address type
        acceptor_address: the acceptor address
        application_data: additional application-specific data
    """

    initiator_address_type: t.Optional[int]
    initiator_address: t.Optional[bytes]
    acceptor_address_type: t.Optional[int]
    acceptor_address: t.Optional[bytes]
    application_data: t.Optional[bytes]

    def __init__(
        self,
        initiator_address_type: t.Optional[int] = None,
        initiator_address: t.Optional[bytes] = None,
        acceptor_address_type: t.Optional[int] = None,
        acceptor_address: t.Optional[bytes] = None,
        application_data: t.Optional[bytes] = None,
    ) -> None: ...
