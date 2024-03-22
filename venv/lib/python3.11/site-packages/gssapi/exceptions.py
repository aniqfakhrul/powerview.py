import typing as t

from gssapi.raw.exceptions import *  # noqa
from gssapi.raw.misc import GSSError  # noqa

"""High-Level API Errors

This module includes several high-level exceptions,
in addition to GSSError and exceptions from
:mod:`gssapi.raw.exceptions`.
"""


# non-GSS exceptions
class GeneralError(Exception):
    """A General High-Level API Error"""
    MAJOR_MESSAGE = "General error"
    FMT_STR = "{maj}: {min}."

    def __init__(
        self,
        minor_message: str,
        **kwargs: str,
    ) -> None:
        maj_str = self.MAJOR_MESSAGE.format(**kwargs)
        err_str = self.FMT_STR.format(maj=maj_str, min=minor_message)
        super(GeneralError, self).__init__(err_str)


class UnknownUsageError(GeneralError):
    """An Error indicating an unknown usage type"""
    MAJOR_MESSAGE = "Unable to determine {obj} usage"


class EncryptionNotUsed(GeneralError):
    """An Error indicating that encryption was requested, but not used"""
    MAJOR_MESSAGE = "Confidentiality was requested, but not used"

    def __init__(
        self,
        minor_message: str,
        unwrapped_message: t.Optional[bytes] = None,
        **kwargs: str,
    ) -> None:
        super(EncryptionNotUsed, self).__init__(minor_message, **kwargs)

        self.unwrapped_message = unwrapped_message
