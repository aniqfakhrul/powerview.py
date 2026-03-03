import base64
import logging

from ldap3.protocol.rfc4511 import Control

# OIDs that the ADWS server explicitly blocks (from Microsoft.ActiveDirectory.WebServices.dll)
BLOCKED_OIDS = {
    "1.2.840.113556.1.4.528",   # Server-side notification
    "1.2.840.113556.1.4.1907",  # LDAP_SERVER_SHUTDOWN_NOTIFY_OID
}

# Paged results control — ADWS uses WS-Enumeration instead
PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"


def _extract_control_fields(control):
    """Extract (oid, criticality, value) from either an ldap3 Control ASN1 object
    or a 3-tuple, matching the pattern used by ldap3's build_controls_list().

    Returns:
        tuple: (oid: str, criticality: bool, value: bytes|None)
    """
    if isinstance(control, Control):
        oid = str(control['controlType'])
        criticality = bool(control['criticality'])
        control_value = control['controlValue']
        if control_value.hasValue():
            value = bytes(control_value)
        else:
            value = None
        return oid, criticality, value

    # 3-tuple format: (oid, criticality, value)
    if len(control) == 3 and isinstance(control[1], bool):
        return str(control[0]), control[1], control[2]

    raise ValueError(f"Unsupported control format: {type(control)}")


def serialize_controls(controls) -> str:
    """Serialize ldap3 Control objects into ADWS XML <ad:controls> block.

    Accepts the same control formats as ldap3's build_controls_list():
      - None or empty list
      - A single ldap3 Control (pyasn1 Sequence) object
      - A 3-tuple (oid, criticality, value)
      - A list of any mix of the above

    Returns:
        Empty string when no controls (template produces clean XML),
        or an <ad:controls>...</ad:controls> XML fragment.
    """
    if not controls:
        return ""

    if not isinstance(controls, list):
        controls = [controls]

    parts = []
    for control in controls:
        oid, criticality, value = _extract_control_fields(control)

        # Skip paged results — ADWS uses WS-Enumeration
        if oid == PAGED_RESULTS_OID:
            continue

        # Warn and skip server-blocked OIDs
        if oid in BLOCKED_OIDS:
            logging.warning(f"[ADWS] Skipping server-blocked control OID: {oid}")
            continue

        crit_str = "true" if criticality else "false"

        if value is not None:
            if isinstance(value, (bytes, bytearray)):
                encoded = base64.b64encode(value).decode("ascii")
            else:
                encoded = base64.b64encode(bytes(value)).decode("ascii")
            parts.append(
                f'<ad:control type="{oid}" criticality="{crit_str}">'
                f'<ad:controlValue xsi:type="xsd:base64Binary">{encoded}</ad:controlValue>'
                f'</ad:control>'
            )
        else:
            parts.append(f'<ad:control type="{oid}" criticality="{crit_str}" />')

    if not parts:
        return ""

    return "<ad:controls>" + "".join(parts) + "</ad:controls>"
