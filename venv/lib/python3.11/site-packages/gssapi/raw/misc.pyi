import typing as t

from gssapi.raw.names import Name
from gssapi.raw.oids import OID
from gssapi.raw.types import MechType


def indicate_mechs() -> t.Set[OID]:
    """Get the currently supported mechanisms.

    This method retrieves the currently supported GSSAPI mechanisms.
    Note that if unknown mechanims are found, those will be skipped.
    """


def inquire_names_for_mech(
    mech: OID,
) -> t.Set[OID]:
    """
    inquire_names_for_mech(mech)
    Get the name types supported by a mechanism.

    This method retrieves the different name types supported by
    the given mechanism.

    Args:
        mech (~gssapi.OID): the mechanism in question

    Returns:
        list: the name type OIDs supported by the given mechanism

    Raises:
        ~gssapi.exceptions.GSSError
    """


def inquire_mechs_for_name(
    name: Name,
) -> t.Set[OID]:
    """
    inquire_mechs_for_name(name)
    List the mechanisms which can process a name.

    This method lists the mechanisms which may be able to
    process the given name.

    Args:
        name (~gssapi.raw.names.Name): the name in question

    Returns:
        The mechanism OIDs able to process the given name

    Raises:
        ~gssapi.exceptions.GSSError
    """


def _display_status(
    error_code: int,
    is_major_code: bool,
    mech: t.Optional[MechType] = None,
    message_context: int = 0,
) -> t.Tuple[bytes, int, bool]:
    """
    Display a string message for a GSSAPI error code.

    This method displays a message for a corresponding GSSAPI error code.
    Since some error codes might have multiple messages, a context parameter
    may be passed to indicate where in the series of messages we currently are
    (this is the second item in the return value tuple).  Additionally, the
    third item in the return value tuple indicates whether or not more
    messages are available.

    Args:
        error_code (int): The error code in question
        is_major_code (bool): is this a major code (True) or a
            minor code (False)
        mech (~gssapi.raw.types.MechType): The mechanism type that returned
            this error code (defaults to None, for the default mechanism)
        message_context (int): The context for this call -- this is used when
            multiple messages are available (defaults to 0)

    Returns:
        (bytes, int, bool): the message, the new message context, and
            whether or not to call again for further messages

    Raises:
       ValueError
    """


class GSSError(Exception):
    """
    A GSSAPI Error

    This Exception represents an error returned from the GSSAPI
    C bindings.  It contains the major and minor status codes
    returned by the method which caused the error, and can
    generate human-readable string messages from the error
    codes
    """

    maj_code: int
    min_code: int
    token: t.Optional[bytes]
    calling_code: int
    routine_code: int
    supplementary_code: int

    @classmethod
    def _parse_major_code(
        cls,
        maj_code: int
    ) -> t.Tuple[int, int, int]: ...

    def __init__(
        self,
        maj_code: int,
        min_code: int,
        token: t.Optional[bytes] = None,
    ) -> None:
        """
        Create a new GSSError.

        This method creates a new GSSError,
        retrieves the related human-readable
        string messages, and uses the results to construct an
        exception message

        Args:
            maj_code: the major code associated with this error
            min_code: the minor code associated with this error
            token: an error token associated with the error
        """

    def get_all_statuses(
        self,
        code: int,
        is_maj: bool,
    ) -> t.List[str]:
        """
        Retrieve all messages for a status code.

        This method retrieves all human-readable messages
        available for the given status code.

        Args:
            code: the status code in question
            is_maj: whether this is a major status code (True)
                or minor status code (False)

        Returns:
            [str]: A list of string messages associated with the
                given code
        """

    def gen_message(self) -> str:
        """
        Retrieves all messages for this error's status codes

        This method retrieves all messages for this error's status codes,
        and forms them into a string for use as an exception message

        Returns:
            str: a string for use as this error's message
        """
