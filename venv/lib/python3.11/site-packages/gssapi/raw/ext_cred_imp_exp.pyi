"""Credentials Import/Export Extension"""

import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.creds import Creds


def export_cred(
    creds: "Creds",
) -> bytes:
    """Export GSSAPI credentials.

    This method exports GSSSAPI credentials into a token
    which may be transmitted between different processes.

    Args:
        creds (Creds): the credentials object to be exported

    Returns:
        bytes: the exported token representing the given credentials object

    Raises:
        ~gssapi.exceptions.GSSError
    """


def import_cred(
    token: bytes,
) -> "Creds":
    """Import GSSAPI credentials from a token.

    This method imports a credentials object from a token
    previously exported by :func:`export_cred`.

    Args:
        token (bytes): the token to import

    Returns:
        Creds: the imported credentials object

    Raises:
        ~gssapi.exceptions.GSSError
    """
