"""Shared error hint resolution for LDAP/ADWS result codes.

Maps (ldap_result_code, win32_error_code) tuples to human-readable hints.
Used by both ADWS error handling and LDAP result processing across powerview.
"""

import re

# Matches the 8-char hex Win32 error code at the start of LDAP extended error messages.
# Example: "0000202F: RefErr: DSID-03100802, data 0" → 0x202F = 8239
_WIN32_HEX_RE = re.compile(r'^([0-9a-fA-F]{8}):?\s')

# (ldap_result_code, win32_error_code) → human-readable hint
# win32_error_code=0 acts as a fallback when no specific Win32 code matches.
# can refer here https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
ERROR_HINTS = {
    # Constraint violations
    (19, 8239): "Password doesn't meet policy (length/complexity/history)",  # ADWS Win32ErrorCode
    (19, 1325): "Password doesn't meet policy (length/complexity/history)",  # LDAP 0x0000052D [ERROR_PASSWORD_RESTRICTION]
    (19, 0):    "Constraint violation (syntax, range, or schema)",

    # Access / auth
    (50, 0):    "Insufficient access rights",
    (49, 0):    "Invalid credentials",
    (49, 1326): "Unknown username or bad password",
    (49, 1331): "Account is disabled",
    (49, 1909): "Account is locked out",

    # Object lifecycle
    (32, 0):    "Object not found — verify DN",
    (68, 0):    "Object already exists",

    # Server refusals
    (53, 0):    "Server unwilling to perform",
    (53, 8233): "Attribute may be read-only or system-controlled",

    # Naming
    (64, 0):    "Naming violation — DN or RDN is invalid",

    # Limits
    (4, 0):     "Size limit exceeded",
    (3, 0):     "Time limit exceeded",
}


def resolve_hint(result_code, win32_error_code=0):
    """Look up a human-readable hint from LDAP result code + Win32 code.

    Args:
        result_code:      LDAP result code (int or None)
        win32_error_code: Win32 error code (int, default 0)

    Returns:
        str or None: Hint message, or None if no match.
    """
    try:
        errorcode = int(result_code) if result_code is not None else None
    except (ValueError, TypeError):
        return None
    if errorcode is None:
        return None

    hint = ERROR_HINTS.get((errorcode, win32_error_code))
    if hint is None and win32_error_code != 0:
        hint = ERROR_HINTS.get((errorcode, 0))
    return hint


def parse_win32_from_ldap_message(message):
    """Extract Win32 error code from an LDAP extended error message.

    LDAP extended error messages start with an 8-char hex Win32 error code:
        "0000202F: RefErr: DSID-03100802, data 0"  → 0x202F = 8239
        "0000052D: AtrErr: DSID-031A1236, ..."     → 0x052D = 1325

    Args:
        message: LDAP extended error message string

    Returns:
        int: Win32 error code, or 0 if not found.
    """
    if not message:
        return 0
    m = _WIN32_HEX_RE.match(message)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    return 0


def patch_ldap3_exceptions():
    """Monkey-patch ldap3's LDAPOperationResult to include error hints.

    Adds a `hint` attribute and appends it to __str__() output,
    matching the ADWS error hint behavior.
    """
    from ldap3.core.exceptions import LDAPOperationResult

    _original_init = LDAPOperationResult.__init__

    def _init_with_hint(self, result=None, description=None, dn=None,
                        message=None, response_type=None, response=None):
        _original_init(self, result, description, dn, message, response_type, response)
        win32 = parse_win32_from_ldap_message(self.message or '')
        self.hint = resolve_hint(self.result, win32)

    def _str_with_hint(self):
        s = [self.__class__.__name__,
             str(self.result) if self.result else None,
             self.description if self.description else None,
             self.dn if self.dn else None,
             self.message if self.message else None,
             self.type if self.type else None]

        out = ' - '.join([str(item) for item in s if item is not None])
        hint = getattr(self, 'hint', None)
        if hint:
            out += f' - HINT: {hint}'
        return out

    LDAPOperationResult.__init__ = _init_with_hint
    LDAPOperationResult.__str__ = _str_with_hint
