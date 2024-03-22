import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.chan_bindings import ChannelBindings
    from gssapi.raw.creds import Creds
    from gssapi.raw.named_tuples import (
        AcceptSecContextResult,
        InitSecContextResult,
        InquireContextResult,
    )
    from gssapi.raw.names import Name
    from gssapi.raw.oids import OID
    from gssapi.raw.types import RequirementFlag

class SecurityContext:
    """
    A GSSAPI Security Context
    """

    def __new__(
        cls,
        cpy: t.Optional["SecurityContext"] = None,
    ) -> "SecurityContext": ...

    @property
    def _started(self) -> bool: ...


def init_sec_context(
    name: "Name",
    creds: t.Optional["Creds"] = None,
    context: t.Optional[SecurityContext] = None,
    mech: t.Optional["OID"] = None,
    flags: t.Optional[t.Union[
        int, "RequirementFlag",
        t.Iterable[int], t.Iterable["RequirementFlag"]
    ]] = None,
    lifetime: t.Optional[int] = None,
    channel_bindings: t.Optional["ChannelBindings"] = None,
    input_token: t.Optional[bytes] = None,
) -> "InitSecContextResult":
    """Initiate a GSSAPI security context.

    This method initiates a GSSAPI security context, targeting the given
    target name.  To create a basic context, just provide the target name.
    Further calls used to update the context should pass in the output context
    of the last call, as well as the input token received from the acceptor.

    Warning:
        This changes the input context!

    Args:
        target_name (~gssapi.raw.names.Name): the target for the security
            context
        creds (Creds): the credentials to use to initiate the context,
            or None to use the default credentials
        context (~gssapi.raw.sec_contexts.SecurityContext): the security
            context to update, or None to create a new context
        mech (~gssapi.raw.types.MechType): the mechanism type for this security
            context, or None for the default mechanism type
        flags (list): the flags to request for the security context, or
            None to use the default set: mutual_authentication and
            out_of_sequence_detection.  This may also be an
            :class:`IntEnumFlagSet`
        lifetime (int): the request lifetime of the security context in seconds
            (a value of 0 or None means indefinite)
        channel_bindings (ChannelBindings): The channel bindings (or None for
            no channel bindings)
        input_token (bytes): the token to use to update the security context,
            or None if you are creating a new context

    Returns:
        InitSecContextResult: the output security context, the actual mech
        type, the actual flags used, the output token to send to the acceptor,
        the actual lifetime of the context in seconds (or None if not supported
        or indefinite), and whether or not more calls are needed to finish the
        initiation.

    Raises:
        ~gssapi.exceptions.InvalidTokenError
        ~gssapi.exceptions.InvalidCredentialsError
        ~gssapi.exceptions.MissingCredentialsError
        ~gssapi.exceptions.ExpiredCredentialsError
        ~gssapi.exceptions.BadChannelBindingsError
        ~gssapi.exceptions.BadMICError
        ~gssapi.exceptions.ExpiredTokenError
        ~gssapi.exceptions.DuplicateTokenError
        ~gssapi.exceptions.MissingContextError
        ~gssapi.exceptions.BadNameTypeError
        ~gssapi.exceptions.BadNameError
        ~gssapi.exceptions.BadMechanismError
    """


def accept_sec_context(
    input_token: bytes,
    acceptor_creds: t.Optional["Creds"] = None,
    context: t.Optional[SecurityContext] = None,
    channel_bindings: t.Optional["ChannelBindings"] = None,
) -> "AcceptSecContextResult":
    """Accept a GSSAPI security context.

    This method accepts a GSSAPI security context using a token sent by the
    initiator, using the given credentials.  It can either be used to accept a
    security context and create a new security context object, or to update an
    existing security context object.

    Warning:
        This changes the input context!

    Args:
        input_token (bytes): the token sent by the context initiator
        acceptor_creds (Creds): the credentials to be used to accept the
            context (or None to use the default credentials)
        context (~gssapi.raw.sec_contexts.SecurityContext): the security
            context to update (or None to create a new security context object)
        channel_bindings (ChannelBindings): The channel bindings (or None for
            no channel bindings)

    Returns:
        AcceptSecContextResult: the resulting security context, the initiator
        name, the mechanism being used, the output token, the flags in use,
        the lifetime of the context in seconds (or None for indefinite or not
        supported), the delegated credentials (valid only if the
        delegate_to_peer flag is set), and whether or not further token
        exchanges are needed to finalize the security context.

    Raises:
        ~gssapi.exceptions.InvalidTokenError
        ~gssapi.exceptions.InvalidCredentialsError
        ~gssapi.exceptions.MissingCredentialsError
        ~gssapi.exceptions.ExpiredCredentialsError
        ~gssapi.exceptions.BadChannelBindingsError
        ~gssapi.exceptions.MissingContextError
        ~gssapi.exceptions.BadMICError
        ~gssapi.exceptions.ExpiredTokenError
        ~gssapi.exceptions.DuplicateTokenError
        ~gssapi.exceptions.BadMechanismError
    """


def inquire_context(
    context: SecurityContext,
    initiator_name: bool = True,
    target_name: bool = True,
    lifetime: bool = True,
    mech: bool = True,
    flags: bool = True,
    locally_init: bool = True,
    complete: bool = True,
) -> "InquireContextResult":
    """Get information about a security context.

    This method obtains information about a security context, including
    the initiator and target names, as well as the TTL, mech,
    flags, and its current state (open vs closed).

    Note:
        the target name may be ``None`` if it would have been ``GSS_C_NO_NAME``

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the context in
            question

    Returns:
        InquireContextResult: the initiator name, the target name, the TTL
        (can be None for indefinite or not supported), the mech type, the
        flags, whether or not the context was locally initiated,
        and whether or not the context is currently fully established

    Raises:
        ~gssapi.exceptions.MissingContextError
    """


def context_time(
    context: SecurityContext,
) -> int:
    """Get the amount of time for which the given context will remain valid.

    This method determines the amount of time for which the given
    security context will remain valid.  An expired context will
    give a result of 0.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the security
            context in question

    Returns:
        int: the number of seconds for which the context will be valid

    Raises:
        ~gssapi.exceptions.ExpiredContextError
        ~gssapi.exceptions.MissingContextError
    """


def process_context_token(
    context: SecurityContext,
    token: bytes,
) -> None:
    """Process a token asynchronously.

    This method provides a way to process a token, even if the
    given security context is not expecting one.  For example,
    if the initiator has the initSecContext return that the context
    is complete, but the acceptor is unable to accept the context,
    and wishes to send a token to the initiator, letting the
    initiator know of the error.

    Warning:
        This method has been essentially deprecated by :rfc:`2744`.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the security
            context against which to process the token
        token (bytes): the token to process

    Raises:
        ~gssapi.exceptions.InvalidTokenError
        ~gssapi.exceptions.MissingContextError
    """


def import_sec_context(
    token: bytes,
) -> SecurityContext:
    """Import a context from another process.

    This method imports a security context established in another process
    by reading the specified token which was output by
    :func:`export_sec_context`.

    Raises:
        ~gssapi.exceptions.MissingContextError
        ~gssapi.exceptions.InvalidTokenError
        ~gssapi.exceptions.OperationUnavailableError
        ~gssapi.exceptions.UnauthorizedError
    """


def export_sec_context(
    context: SecurityContext,
) -> bytes:
    """Export a context for use in another process.

    This method exports a security context, deactivating in the current process
    and creating a token which can then be imported into another process
    with :func:`import_sec_context`.

    Warning: this modifies the input context

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the context to send
            to another process

    Returns:
        bytes: the output token to be imported

    Raises:
        ~gssapi.exceptions.ExpiredContextError
        ~gssapi.exceptions.MissingContextError
        ~gssapi.exceptions.OperationUnavailableError
    """


def delete_sec_context(
    context: SecurityContext,
    local_only: bool = True,
) -> bytes:
    """Delete a GSSAPI security context.

    This method deletes a GSSAPI security context,
    returning an output token to send to the other
    holder of the security context to notify them
    of the deletion.

    Note:
        This method generally should not be used.  :class:`SecurityContext`
        objects will automatically be freed by Python.

    Args:
        context (~gssapi.raw.sec_contexts.SecurityContext): the security
            context in question
        local_only (bool): should we request local deletion (True), or also
            remote deletion (False), in which case a token is also returned

    Returns:
        bytes: the output token (if remote deletion is requested).  Generally
            this is None, but bytes for compatibility.

    Raises:
        ~gssapi.exceptions.MissingContextError
    """
