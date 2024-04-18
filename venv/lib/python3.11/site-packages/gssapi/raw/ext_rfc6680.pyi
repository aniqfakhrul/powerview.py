import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.named_tuples import (
        GetNameAttributeResult,
        InquireNameResult,
    )
    from gssapi.raw.names import Name
    from gssapi.raw.oids import OID


def display_name_ext(
    name: "Name",
    name_type: "OID",
) -> bytes:
    """Display the given Name using the given name type.

    This method attempts to display the given Name using the syntax of
    the given name type.  If this is not possible, an appropriate error
    will be raised.

    Args:
        name (~gssapi.raw.names.Name): the name to display
        name_type (~gssapi.OID): the name type (see NameType) to use to
            display the given name

    Returns:
        bytes: the displayed name

    Raises:
        ~gssapi.exceptions.OperationUnavailableError: the given name could not
            be displayed using the given name type
    """


def inquire_name(
    name: "Name",
    mech_name: bool = True,
    attrs: bool = True,
) -> "InquireNameResult":
    """Get information about a Name.

    This method retrieves information about the given name, including
    the set of attribute names for the given name, as well as whether or
    not the name is a mechanism name.  Additionally, if the given name is
    a mechanism name, the associated mechansim is returned as well.

    Args:
        name (~gssapi.raw.names.Name): the name about which to inquire
        mech_name (bool): whether or not to retrieve if this name
            is a mech_name (and the associate mechanism)
        attrs (bool): whether or not to retrieve the attribute name list

    Returns:
        InquireNameResult: the set of attribute names for the given name,
        whether or not the name is a Mechanism Name, and potentially
        the associated mechanism if it is a Mechanism Name

    Raises:
        ~gssapi.exceptions.GSSError
    """


def set_name_attribute(
    name: "Name",
    attr: bytes,
    value: t.Iterable[bytes],
    complete: bool = False,
) -> None:
    """Set the value(s) of a name attribute.

    This method sets the value(s) of the given attribute on the given name.

    Note that this functionality more closely matches the pseudo-API
    presented in RFC 6680, not the C API (which uses multiple calls to
    add multiple values).  However, multiple calls to this method will
    continue adding values, so :func:`delete_name_attribute` must be
    used in between calls to "clear" the values.

    Args:
        name (~gssapi.raw.names.Name): the Name on which to set the attribute
        attr (bytes): the name of the attribute
        value (list): a list of bytes objects to use as the value(s)
        complete (bool): whether or not to mark this attribute's value
            set as being "complete"

    Raises:
        ~gssapi.exceptions.OperationUnavailableError: the given attribute name
            is unknown or could not be set
    """


def get_name_attribute(
    name: "Name",
    attr: bytes,
    more: t.Optional[int] = None,
) -> "GetNameAttributeResult":
    """Get the value(s) of a name attribute.

    This method retrieves the value(s) of the given attribute
    for the given Name.

    Note that this functionality matches pseudo-API presented
    in RFC 6680, not the C API (which uses a state variable and
    multiple calls to retrieve multiple values).

    Args:
        name (~gssapi.raw.names.Name): the Name from which to get the attribute
        attr (bytes): the name of the attribute

    Returns:
        GetNameAttributeResult: the raw version of the value(s),
        the human-readable version of the value(s), whether
        or not the attribute was authenticated, and whether or
        not the attribute's value set was marked as complete

    Raises:
        ~gssapi.exceptions.OperationUnavailableError: the given attribute is
            unknown or unset
    """


def delete_name_attribute(
    name: "Name",
    attr: bytes,
) -> None:
    """Remove an attribute from a name.

    This method removes an attribute from a Name.  This method may be
    used before :func:`set_name_attribute` clear the values of an attribute
    before setting a new value (making the latter method work like a 'set'
    operation instead of an 'add' operation).

    Note that the removal of certain attributes may not be allowed.

    Args:
        name (~gssapi.raw.names.Name): the name to remove the attribute from
        attr (bytes): the name of the attribute

    Raises:
        ~gssapi.exceptions.OperationUnavailableError
        ~gssapi.exceptions.UnauthorizedError
    """


def export_name_composite(
    name: "Name",
) -> bytes:
    """Export a name, preserving attribute information.

    This method functions similarly to :func:`~gssapi.raw.names.export_name`,
    except that it preserves attribute information.  The resulting bytes may be
    imported using :func:`~gssapi.raw.names.import_name` with the
    :attr:`~gssapi.raw.types.NameType.composite_export` name type.

    Note:
        Some versions of MIT Kerberos require you to either canonicalize a name
        once it has been imported with composite-export name type, or to import
        using the normal export name type.

    Args:
        name (~gssapi.raw.names.Name): the name to export

    Returns:
        bytes: the exported composite name

    Raises:
        ~gssapi.exceptions.GSSError
    """
