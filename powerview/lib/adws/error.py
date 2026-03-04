import re
import xml.etree.ElementTree as ET
from .templates import NAMESPACES
from ldap3.core.results import RESULT_CODES as RESULT_DESCRIPTIONS
from powerview.utils.hints import resolve_hint

_BARE_AMP_RE = re.compile(r'&(?!(?:amp|lt|gt|apos|quot|#\d+|#x[0-9a-fA-F]+);)')


def _normalize_referrals(raw):
    """Normalize referral data to a list of strings or None."""
    if isinstance(raw, list):
        return raw if raw else None
    if isinstance(raw, dict):
        # Dict from _parse_element — collect all string values
        vals = [v for v in raw.values() if isinstance(v, str) and v.strip()]
        return vals if vals else None
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return None


class ADWSError(Exception):
    """ADWS SOAP fault exception with ldap3-compatible error formatting.

    Mirrors ldap3's LDAPOperationResult for consistent error handling.

    Can be constructed two ways:
      1. From fault data:  ADWSError(xml_string) or ADWSError(fault_dict)
      2. Structured:       ADWSError(result=68, dn='...', message='...', response_type='addResponse')
    """

    def __init__(self, fault_data=None, *, result=None, description=None,
                 dn='', message='', response_type='', win32_error_code=0,
                 response=None, referrals=None):
        # ldap3-compatible fields
        self.result = result
        self.description = description or ''
        self.dn = dn or ''
        self.message = message or ''
        self.type = response_type or ''
        self.response = response
        self.referrals = referrals

        # ADWS-specific fields
        self.hint = None
        self.short_message = ''
        self.win32_error_code = win32_error_code or 0
        self.raw_fault = ''

        # Parse fault_data if provided (raw XML string or dict)
        if fault_data is not None:
            self._parse_fault_data(fault_data)

        # Auto-lookup description from result code
        if self.result is not None and not self.description:
            try:
                self.description = RESULT_DESCRIPTIONS.get(int(self.result), 'other')
            except (ValueError, TypeError):
                self.description = 'other'

        self._resolve_hint()
        super().__init__(str(self))

    # -- Fault data parsers ------------------------------------------------

    def _parse_fault_data(self, fault_data):
        if isinstance(fault_data, str):
            self.raw_fault = fault_data
            self._parse_string_fault(fault_data)
        elif isinstance(fault_data, dict):
            self._parse_dict_fault(fault_data)

    def _parse_string_fault(self, data):
        """Parse from raw XML string or plain error message."""
        xml_data = data
        if data.startswith("Sorting or Selection Property is invalid."):
            xml_start = data.find("<")
            if xml_start != -1:
                xml_data = data[xml_start:]

        try:
            for prefix, uri in NAMESPACES.items():
                ET.register_namespace(prefix, uri)
            root = ET.fromstring(xml_data)
        except ET.ParseError:
            try:
                root = ET.fromstring(_BARE_AMP_RE.sub('&amp;', xml_data))
            except ET.ParseError:
                # Not XML — treat entire string as the message
                if not self.message:
                    self.message = data
                return

        self._extract_from_xml(root)

    def _parse_dict_fault(self, fault_dict):
        """Parse from response dict (from *_response_to_dict)."""
        error_detail = fault_dict.get("ErrorDetail", {})

        # Navigate: ErrorDetail -> FaultDetail (or first nested dict)
        fault_detail = error_detail.get("FaultDetail")
        if fault_detail is None:
            for _val in error_detail.values():
                if isinstance(_val, dict):
                    fault_detail = _val
                    break
        if not isinstance(fault_detail, dict):
            fault_detail = {}

        # Find specific error dict (DirectoryError, ArgumentError, etc.)
        specific_error = {}
        if fault_detail:
            for key in ("DirectoryError", "ArgumentError"):
                if key in fault_detail and isinstance(fault_detail[key], dict):
                    specific_error = fault_detail[key]
                    break
            else:
                for _val in fault_detail.values():
                    if isinstance(_val, dict):
                        specific_error = _val
                        break

        # Extract fields
        if self.result is None:
            code = specific_error.get("ErrorCode", fault_detail.get("ErrorCode"))
            if code is not None:
                try:
                    self.result = int(code)
                except (ValueError, TypeError):
                    pass

        ext_msg = specific_error.get("ExtendedErrorMessage",
                  fault_detail.get("ExtendedErrorMessage", "")).strip()
        short_msg = specific_error.get("Message", "").strip()
        reason_text = fault_dict.get("Error", "").strip()

        if not self.message:
            self.message = ext_msg or short_msg or reason_text
        elif ext_msg:
            # Prefer ExtendedErrorMessage even if message was already set
            self.message = ext_msg

        if short_msg:
            self.short_message = short_msg

        try:
            self.win32_error_code = int(specific_error.get("Win32ErrorCode", 0))
        except (ValueError, TypeError):
            self.win32_error_code = 0

        # Extract referrals
        raw_referral = specific_error.get("Referral")
        if raw_referral and self.referrals is None:
            self.referrals = _normalize_referrals(raw_referral)

    def _extract_from_xml(self, root):
        """Extract error fields from parsed SOAP fault XML."""
        detail = (root.find(".//soapenv:Detail", NAMESPACES)
                  or root.find(".//s:Detail", NAMESPACES))

        if detail is not None:
            dir_error = detail.find(".//ad:DirectoryError", NAMESPACES)
            if dir_error is not None:
                code = (dir_error.find("ad:ErrorCode", NAMESPACES))
                msg = (dir_error.find("ad:Message", NAMESPACES))
                ext_msg = (dir_error.find("ad:ExtendedErrorMessage", NAMESPACES))
                matched_dn = (dir_error.find("ad:MatchedDN", NAMESPACES))
                win32 = (dir_error.find("ad:Win32ErrorCode", NAMESPACES))

                if code is not None and code.text and self.result is None:
                    try:
                        self.result = int(code.text.strip())
                    except (ValueError, TypeError):
                        pass

                ext_text = ext_msg.text.strip() if ext_msg is not None and ext_msg.text else ''
                msg_text = msg.text.strip() if msg is not None and msg.text else ''

                if ext_text:
                    self.message = ext_text
                if msg_text:
                    self.short_message = msg_text
                    if not self.message:
                        self.message = msg_text

                if matched_dn is not None and matched_dn.text and matched_dn.text.strip() and not self.dn:
                    self.dn = matched_dn.text.strip()

                try:
                    self.win32_error_code = int(win32.text.strip()) if win32 is not None and win32.text else 0
                except (ValueError, TypeError):
                    self.win32_error_code = 0

                # Extract referrals from <ad:Referral> children
                if self.referrals is None:
                    referral_elem = dir_error.find("ad:Referral", NAMESPACES)
                    if referral_elem is not None:
                        refs = [child.text.strip() for child in referral_elem
                                if child.text and child.text.strip()]
                        self.referrals = refs if refs else None
                return

            # Check for EnumerateFault
            enum_fault = detail.find(".//ad:EnumerateFault", NAMESPACES)
            if enum_fault is not None:
                error_elem = enum_fault.find(".//ad:Error", NAMESPACES)
                if error_elem is not None and error_elem.text and not self.message:
                    self.message = error_elem.text.strip()
                return

        # Fall back to Reason/Text
        reason = (root.find(".//soapenv:Text", NAMESPACES)
                  or root.find(".//s:Text", NAMESPACES))
        if reason is not None and reason.text and not self.message:
            self.message = reason.text.strip()

    # -- Hint resolution ---------------------------------------------------

    def _resolve_hint(self):
        """Look up a human-readable hint from error code + Win32 code."""
        self.hint = resolve_hint(self.result, self.win32_error_code)

    # -- String representation ---------------------------------------------

    def __str__(self):
        """Format like ldap3's LDAPOperationResult.__str__().

        Example:
            ADWSError - 68 - entryAlreadyExists - CN=test,DC=dom,DC=local
                      - 00000524: UpdErr: DSID-031A11EE, problem 6005 ... - addResponse
        """
        parts = ['ADWSError']
        if self.result is not None:
            parts.append(str(self.result))
        if self.description:
            parts.append(self.description)
        if self.dn:
            parts.append(self.dn)
        if self.message:
            parts.append(self.message)
        if self.type:
            parts.append(self.type)

        s = ' - '.join(parts)
        if self.hint:
            s += f' - HINT: {self.hint}'
        return s
