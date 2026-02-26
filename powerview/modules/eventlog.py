import struct
import uuid
import re
import logging
import os
import tempfile
from datetime import datetime, timezone

from impacket.dcerpc.v5 import even6
from impacket.dcerpc.v5.dtypes import LPWSTR, WSTR, DWORD
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


# Workaround for impacket bug on Server 2025: ChannelPath must be LPWSTR, not WSTR
class EvtRpcExportLogFixed(NDRCALL):
    opnum = 7
    structure = (
        ('Handle', even6.CONTEXT_HANDLE_OPERATION_CONTROL),
        ('ChannelPath', LPWSTR),
        ('Query', WSTR),
        ('BackupPath', WSTR),
        ('Flags', DWORD),
    )


################################################################################
# BinXML Parser (MS-EVEN6 Binary XML)
################################################################################

class BinXmlSubstitution:
    def __init__(self, buf, offset):
        (sub_token, sub_id, sub_type) = struct.unpack_from("<BHB", buf, offset)
        self.length = 4
        self._id = sub_id
        self._type = sub_type
        self._optional = sub_token == 0x0e

    def xml(self, template=None):
        value = template.values[self._id]
        if value.type == 0x0:
            return None if self._optional else ""
        if self._type == 0x1:
            return value.data.decode("utf16")
        elif self._type == 0x4:
            return str(struct.unpack("<B", value.data)[0])
        elif self._type == 0x6:
            return str(struct.unpack("<H", value.data)[0])
        elif self._type == 0x8:
            return str(struct.unpack("<I", value.data)[0])
        elif self._type == 0xa:
            return str(struct.unpack("<Q", value.data)[0])
        elif self._type == 0x11:
            return datetime.fromtimestamp(
                struct.unpack("<Q", value.data)[0] / 1e7 - 11644473600,
                tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        elif self._type == 0x13:
            revision, number_of_sub_ids = struct.unpack_from("<BB", value.data)
            iav = int.from_bytes(value.data[2:8], "big")
            sub_ids = [struct.unpack("<I", value.data[8 + 4 * i:12 + 4 * i])[0] for i in range(number_of_sub_ids)]
            return "S-{}-{}-{}".format(revision, iav, "-".join([str(s) for s in sub_ids]))
        elif self._type == 0x15 or self._type == 0x10:
            return value.data.hex()
        elif self._type == 0x21:
            return value.template.xml()
        elif self._type == 0xf:
            return str(uuid.UUID(bytes_le=value.data))
        else:
            return value.data.hex()


class BinXmlValue:
    def __init__(self, buf, offset):
        token, string_type, val_length = struct.unpack_from("<BBH", buf, offset)
        self._val = buf[offset + 4:offset + 4 + val_length * 2].decode("utf16")
        self.length = 4 + val_length * 2

    def xml(self, template=None):
        return self._val


class BinXmlAttribute:
    def __init__(self, buf, offset):
        struct.unpack_from("<B", buf, offset)
        self._name = BinXmlName(buf, offset + 1)
        (next_token,) = struct.unpack_from("<B", buf, offset + 1 + self._name.length)
        if next_token == 0x05 or next_token == 0x45:
            self._value = BinXmlValue(buf, offset + 1 + self._name.length)
        elif next_token == 0x0e or next_token == 0x0d:
            self._value = BinXmlSubstitution(buf, offset + 1 + self._name.length)
        else:
            self._value = None
            logging.debug(f"[BinXml] Unknown attribute next_token {hex(next_token)}")
        self.length = 1 + self._name.length + (self._value.length if self._value else 0)

    def xml(self, template=None):
        if self._value is None:
            return None
        val = self._value.xml(template)
        return None if val is None else f'{self._name.val}="{val}"'


class BinXmlName:
    def __init__(self, buf, offset):
        hashs, name_length = struct.unpack_from("<HH", buf, offset)
        self.val = buf[offset + 4:offset + 4 + name_length * 2].decode("utf16")
        self.length = 4 + (name_length + 1) * 2


class BinXmlElement:
    def __init__(self, buf, offset):
        token, dependency_id, elem_length = struct.unpack_from("<BHI", buf, offset)
        self._name = BinXmlName(buf, offset + 7)
        self._dependency = dependency_id
        ofs = offset + 7 + self._name.length
        if token == 0x41:
            struct.unpack_from("<I", buf, ofs)
            ofs += 4
        self._children = []
        self._attributes = []

        while True:
            next_token = buf[ofs]
            if next_token == 0x06 or next_token == 0x46:
                attr = BinXmlAttribute(buf, ofs)
                self._attributes.append(attr)
                ofs += attr.length
            elif next_token == 0x02:
                self._empty = False
                ofs += 1
                while True:
                    next_token = buf[ofs]
                    if next_token == 0x01 or next_token == 0x41:
                        element = BinXmlElement(buf, ofs)
                    elif next_token == 0x04:
                        ofs += 1
                        break
                    elif next_token == 0x05:
                        element = BinXmlValue(buf, ofs)
                    elif next_token == 0x0e or next_token == 0x0d:
                        element = BinXmlSubstitution(buf, ofs)
                    else:
                        break
                    self._children.append(element)
                    ofs += element.length
                break
            elif next_token == 0x03:
                self._empty = True
                ofs += 1
                break
            else:
                break

        self.length = ofs - offset

    def xml(self, template=None):
        if self._dependency != 0xFFFF and template.values[self._dependency].type == 0x00:
            return ""
        attrs = filter(lambda x: x is not None, (x.xml(template) for x in self._attributes))
        attrs = " ".join(attrs)
        if len(attrs) > 0:
            attrs = " " + attrs
        if self._empty:
            return f"<{self._name.val}{attrs}/>"
        else:
            children = (x.xml(template) for x in self._children)
            return "<{}{}>{}</{}>".format(self._name.val, attrs, "".join(children), self._name.val)


class BinXmlValueSpec:
    def __init__(self, buf, offset, value_offset):
        self.length, self.type, value_eof = struct.unpack_from("<HBB", buf, offset)
        self.data = buf[value_offset:value_offset + self.length]
        if self.type == 0x21:
            self.template = BinXml(buf, value_offset)


class BinXmlTemplateInstance:
    def __init__(self, buf, offset):
        token, unknown0, guid, tmpl_length, next_token = struct.unpack_from("<BB16sIB", buf, offset)
        if next_token == 0x0F:
            self._xml = BinXml(buf, offset + 0x16)
            eof, num_values = struct.unpack_from("<BI", buf, offset + 22 + self._xml.length)
            values_length = 0
            self.values = []
            for x in range(num_values):
                value = BinXmlValueSpec(
                    buf,
                    offset + 22 + self._xml.length + 5 + x * 4,
                    offset + 22 + self._xml.length + 5 + num_values * 4 + values_length
                )
                self.values.append(value)
                values_length += value.length
            self.length = 22 + self._xml.length + 5 + num_values * 4 + values_length
        else:
            self.length = 0

    def xml(self, template=None):
        return self._xml.xml(self)


class BinXml:
    def __init__(self, buf, offset):
        header_token, major_version, minor_version, flags, next_token = struct.unpack_from("<BBBBB", buf, offset)
        if next_token == 0x0C:
            self._element = BinXmlTemplateInstance(buf, offset + 4)
        elif next_token == 0x01 or next_token == 0x41:
            self._element = BinXmlElement(buf, offset + 4)
        else:
            self._element = None
        self.length = 4 + (self._element.length if self._element else 0)

    def xml(self, template=None):
        if self._element is None:
            return ""
        return self._element.xml(template)


class ResultSet:
    def __init__(self, buf):
        total_size, header_size, event_offset, bookmark_offset, binxml_size = struct.unpack_from("<IIIII", buf)
        self._xml = BinXml(buf, 0x14)

    def xml(self):
        return self._xml.xml()


################################################################################
# Event Description / Logon Type Lookups
################################################################################

EVENT_DESCRIPTIONS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4647: "User Initiated Logoff",
    4648: "Logon with Explicit Credentials",
    4672: "Special Privileges Assigned",
    4688: "New Process Created",
    4689: "Process Exited",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4723: "Password Change Attempted",
    4724: "Password Reset Attempted",
    4725: "User Account Disabled",
    4726: "User Account Deleted",
    4728: "Member Added to Security-Enabled Global Group",
    4732: "Member Added to Security-Enabled Local Group",
    4740: "Account Locked Out",
    4756: "Member Added to Security-Enabled Universal Group",
    4768: "Kerberos TGT Requested",
    4769: "Kerberos Service Ticket Requested",
    4770: "Kerberos Service Ticket Renewed",
    4771: "Kerberos Pre-Authentication Failed",
    4776: "NTLM Authentication",
    1102: "Audit Log Cleared",
    7045: "New Service Installed",
}

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

# Accounts to skip when -Raw is not used
SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "DWM-3",
    "UMFD-0", "UMFD-1", "UMFD-2", "UMFD-3", "ANONYMOUS LOGON", "-",
}


################################################################################
# EventLogQuery - Main Class
################################################################################

class EventLogQuery:
    def __init__(self, connection):
        self.conn = connection
        self.dce = None

    def connect_even6(self, host, username=None, password=None, domain=None, lmhash=None, nthash=None):
        """Connect to EVEN6 RPC endpoint. Try TCP EPM first, fall back to named pipe."""
        # Try TCP via EPM first (required for Server 2025)
        try:
            string_binding = hept_map(host, even6.MSRPC_UUID_EVEN6, protocol="ncacn_ip_tcp")
            logging.debug(f"[Get-EventLog] EPM resolved: {string_binding}")
            dce = self.conn.connectRPCTransport(
                host=host,
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                stringBindings=string_binding,
                interface_uuid=even6.MSRPC_UUID_EVEN6,
                authn_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                raise_exceptions=True
            )
            if dce:
                self.dce = dce
                return True
        except Exception as e:
            logging.debug(f"[Get-EventLog] TCP EPM failed: {e}, trying named pipe...")

        # Fallback to named pipe
        try:
            string_binding = r'ncacn_np:%s[\pipe\eventlog]' % host
            dce = self.conn.connectRPCTransport(
                host=host,
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                stringBindings=string_binding,
                interface_uuid=even6.MSRPC_UUID_EVEN6,
                authn_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                raise_exceptions=True
            )
            if dce:
                self.dce = dce
                return True
        except Exception as e:
            logging.error(f"[Get-EventLog] Named pipe fallback failed: {e}")

        return False

    def disconnect(self):
        if self.dce:
            try:
                self.dce.disconnect()
            except Exception:
                pass
            self.dce = None

    @staticmethod
    def _align4(offset):
        return (offset + 3) & ~3

    @staticmethod
    def _parse_lpwstr_array(raw, offset):
        """Parse a conformant array of LPWSTR from NDR wire data."""
        strings = []
        if offset + 4 > len(raw):
            return strings

        max_count = struct.unpack_from('<I', raw, offset)[0]
        offset += 4

        referents = []
        for _ in range(max_count):
            if offset + 4 > len(raw):
                break
            referents.append(struct.unpack_from('<I', raw, offset)[0])
            offset += 4

        for ref in referents:
            if ref == 0:
                continue
            if offset + 12 > len(raw):
                break
            str_max = struct.unpack_from('<I', raw, offset)[0]; offset += 4
            str_off = struct.unpack_from('<I', raw, offset)[0]; offset += 4
            str_act = struct.unpack_from('<I', raw, offset)[0]; offset += 4

            byte_len = str_act * 2
            if offset + byte_len > len(raw):
                break

            data = raw[offset:offset + byte_len]
            offset += byte_len
            offset = EventLogQuery._align4(offset)

            try:
                strings.append(data.decode('utf-16-le').rstrip('\x00'))
            except Exception:
                pass

        return strings

    def list_channels(self):
        """List available event log channels using raw DCE/RPC call.

        Uses manual NDR parsing instead of impacket's hEvtRpcGetChannelList
        which has a conformant array buffer overflow bug on large responses.
        """
        try:
            # EvtRpcGetChannelList (opnum 19), flags = 0
            self.dce.call(19, struct.pack('<I', 0))
            raw = self.dce.recv()
        except Exception as e:
            logging.error(f"[Get-EventLog] Failed to list channels: {e}")
            return []

        if len(raw) < 12:
            logging.error(f"[Get-EventLog] Channel list response too short: {len(raw)} bytes")
            return []

        retval = struct.unpack_from('<I', raw, len(raw) - 4)[0]
        if retval != 0:
            logging.error(f"[Get-EventLog] EvtRpcGetChannelList returned error: 0x{retval:08x}")
            return []

        num_channels = struct.unpack_from('<I', raw, 0)[0]
        ptr = struct.unpack_from('<I', raw, 4)[0]

        if ptr == 0 or num_channels == 0:
            return []

        return self._parse_lpwstr_array(raw, 8)

    def list_publishers(self):
        """List event publishers using raw DCE/RPC call.

        Uses manual NDR parsing instead of impacket's built-in function
        which has a conformant array buffer overflow bug on large responses.
        """
        try:
            # EvtRpcGetPublisherList (opnum 22), flags = 0
            self.dce.call(22, struct.pack('<I', 0))
            raw = self.dce.recv()
        except Exception as e:
            logging.error(f"[Get-EventLog] Failed to list publishers: {e}")
            return []

        if len(raw) < 12:
            logging.error(f"[Get-EventLog] Publisher list response too short: {len(raw)} bytes")
            return []

        retval = struct.unpack_from('<I', raw, len(raw) - 4)[0]
        if retval != 0:
            logging.error(f"[Get-EventLog] EvtRpcGetPublisherList returned error: 0x{retval:08x}")
            return []

        num_publishers = struct.unpack_from('<I', raw, 0)[0]
        ptr = struct.unpack_from('<I', raw, 4)[0]

        if ptr == 0 or num_publishers == 0:
            return []

        return self._parse_lpwstr_array(raw, 8)

    def build_xpath_query(self, event_ids=None, logon_types=None, target_user=None):
        """Build an XPath query for the event log."""
        conditions = []

        if event_ids:
            if len(event_ids) == 1:
                conditions.append(f"EventID={event_ids[0]}")
            else:
                id_list = " or ".join([f"EventID={eid}" for eid in event_ids])
                conditions.append(f"({id_list})")

        system_filter = ""
        if conditions:
            system_filter = f"System[{' and '.join(conditions)}]"

        data_conditions = []
        if logon_types:
            if len(logon_types) == 1:
                data_conditions.append(f"Data[@Name='LogonType']='{logon_types[0]}'")
            else:
                lt_list = " or ".join([f"Data[@Name='LogonType']='{lt}'" for lt in logon_types])
                data_conditions.append(f"({lt_list})")

        if target_user:
            data_conditions.append(f"Data[@Name='TargetUserName']='{target_user}'")

        event_data_filter = ""
        if data_conditions:
            event_data_filter = f"EventData[{' and '.join(data_conditions)}]"

        if system_filter and event_data_filter:
            return f"*[{system_filter} and {event_data_filter}]"
        elif system_filter:
            return f"*[{system_filter}]"
        elif event_data_filter:
            return f"*[{event_data_filter}]"
        else:
            return "*"

    def query_events(self, channel="Security", xpath="*", max_events=100, newest_first=True):
        """Direct query mode using EvtRpcRegisterLogQuery + EvtRpcQueryNext."""
        flags = even6.EvtQueryChannelName
        if newest_first:
            flags |= even6.EvtReadNewestToOldest
        else:
            flags |= even6.EvtReadOldestToNewest

        try:
            query_string = f'<QueryList><Query Id="0"><Select Path="{channel}">{xpath}</Select></Query></QueryList>'
            resp = even6.hEvtRpcRegisterLogQuery(
                self.dce,
                "\x00",
                flags,
                query_string + "\x00"
            )
        except Exception as e:
            logging.error(f"[Get-EventLog] Failed to register log query: {e}")
            return []

        log_handle = resp['Handle']
        events = []
        batch_size = min(100, max_events)

        try:
            while len(events) < max_events:
                remaining = max_events - len(events)
                request_count = min(batch_size, remaining)

                try:
                    resp = even6.hEvtRpcQueryNext(self.dce, log_handle, request_count, timeOutEnd=5000)
                except Exception as e:
                    if 'ERROR_NO_MORE_ITEMS' in str(e) or 'ERROR_TIMEOUT' in str(e):
                        break
                    raise

                num_records = resp['NumActualRecords']
                if num_records == 0:
                    break

                for i in range(num_records):
                    if len(events) >= max_events:
                        break
                    event_offset = resp['EventDataIndices'][i]['Data']
                    event_size = resp['EventDataSizes'][i]['Data']
                    event_data = b"".join(resp['ResultBuffer'][event_offset:event_offset + event_size])
                    events.append(event_data)

                if num_records < request_count:
                    break
        finally:
            try:
                even6.hEvtRpcClose(self.dce, log_handle)
            except Exception:
                pass

        return events

    def export_events(self, channel="Security", xpath="*", host=None, max_events=100,
                      username=None, password=None, domain=None, lmhash=None, nthash=None):
        """Export mode: EvtRpcExportLog to write .evtx on target, download via SMB, parse locally."""
        try:
            from Evtx.Evtx import FileHeader
        except ImportError:
            logging.error("[Get-EventLog] python-evtx is required for export mode. Install with: pip install python-evtx")
            return []

        remote_path = f"C:\\Windows\\Temp\\pv_{os.urandom(4).hex()}.evtx"
        smb_path = remote_path.replace("C:\\", "").replace("\\", "/")

        # Register controllable operation for export
        try:
            ctrl_resp = even6.hEvtRpcRegisterControllableOperation(self.dce)
            ctrl_handle = ctrl_resp['Handle']
        except Exception as e:
            logging.error(f"[Get-EventLog] Failed to register controllable operation: {e}")
            return []

        # Export log
        query_string = f'<QueryList><Query Id="0"><Select Path="{channel}">{xpath}</Select></Query></QueryList>'
        try:
            request = EvtRpcExportLogFixed()
            request['Handle'] = ctrl_handle
            request['ChannelPath'] = channel + "\x00"
            request['Query'] = query_string + "\x00"
            request['BackupPath'] = remote_path + "\x00"
            request['Flags'] = 0
            self.dce.request(request)
            logging.info(f"[Get-EventLog] Exported log to {remote_path} on target")
        except Exception as e:
            logging.error(f"[Get-EventLog] Export failed: {e}")
            try:
                even6.hEvtRpcClose(self.dce, ctrl_handle)
            except Exception:
                pass
            return []

        # Download via SMB
        local_file = None
        events = []
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(host, host)
            if lmhash or nthash:
                smb.login(username or '', password or '', domain or '', lmhash or '', nthash or '')
            else:
                smb.login(username or '', password or '', domain or '')

            local_file = tempfile.NamedTemporaryFile(suffix='.evtx', delete=False)
            smb.getFile('C$', smb_path, local_file.write)
            local_file.close()

            # Parse the evtx file
            with open(local_file.name, 'rb') as f:
                fh = FileHeader(f.read(), 0x0)
                count = 0
                for xml_str, _ in fh.xml_entries():
                    if count >= max_events:
                        break
                    events.append(xml_str)
                    count += 1

            # Clean up remote file
            try:
                smb.deleteFile('C$', smb_path)
                logging.debug(f"[Get-EventLog] Cleaned up {remote_path} on target")
            except Exception as e:
                logging.warning(f"[Get-EventLog] Failed to clean up remote file: {e}")

            smb.logoff()
        except Exception as e:
            logging.error(f"[Get-EventLog] SMB download/parse failed: {e}")
        finally:
            if local_file:
                try:
                    os.unlink(local_file.name)
                except Exception:
                    pass
            try:
                even6.hEvtRpcClose(self.dce, ctrl_handle)
            except Exception:
                pass

        return events

    def parse_event_xml(self, raw_data):
        """Parse a raw BinXML event record into an XML string."""
        try:
            rs = ResultSet(raw_data)
            return rs.xml()
        except Exception as e:
            logging.debug(f"[Get-EventLog] Failed to parse event: {e}")
            return None

    def normalize_event(self, xml_string, raw=False):
        """Extract key fields from an event XML string into a flat dict."""
        if not xml_string:
            return None

        result = {}

        # Extract System fields
        event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml_string)
        if event_id_match:
            result['EventId'] = int(event_id_match.group(1))
            result['Description'] = EVENT_DESCRIPTIONS.get(result['EventId'], "")

        time_match = re.search(r'SystemTime="([^"]+)"', xml_string)
        if time_match:
            result['TimeCreated'] = time_match.group(1)

        computer_match = re.search(r'<Computer>([^<]+)</Computer>', xml_string)
        if computer_match:
            result['Computer'] = computer_match.group(1)

        channel_match = re.search(r'<Channel>([^<]+)</Channel>', xml_string)
        if channel_match:
            result['Channel'] = channel_match.group(1)

        # Extract EventData fields
        data_matches = re.findall(r"<Data Name='([^']+)'>([^<]*)</Data>", xml_string)
        if not data_matches:
            data_matches = re.findall(r'<Data Name="([^"]+)">([^<]*)</Data>', xml_string)

        for name, value in data_matches:
            result[name] = value

        # Add logon type description if present
        if 'LogonType' in result:
            try:
                lt = int(result['LogonType'])
                result['LogonTypeDesc'] = LOGON_TYPES.get(lt, f"Unknown ({lt})")
            except (ValueError, TypeError):
                pass

        # Filter out system/machine accounts unless -Raw
        if not raw:
            target_username = result.get('TargetUserName', '')
            if target_username:
                if target_username.upper() in SYSTEM_ACCOUNTS:
                    return None
                if target_username.endswith('$'):
                    return None

        return result
