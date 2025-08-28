from impacket.structure import Structure
import socket
from struct import unpack, pack
import dns
import datetime

STORED_ADDR = {}

# https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    33: 'SRV',
    65281: 'WINS',
}

class DNS_UTIL:
    def get_next_serial(dnsserver, dc, zone, tcp, timeout=15):
        dnsresolver = dns.resolver.Resolver()
        dnsresolver.timeout = timeout
        if dnsserver:
            server = dnsserver
        else:
            server = dc

        try:
            socket.inet_aton(server)
            dnsresolver.nameservers = [server]
            
        except socket.error:
            pass
        res = dnsresolver.resolve(zone, 'SOA',tcp=tcp)
        for answer in res:
            return answer.serial + 1

    def new_record(rtype, serial, recordaddress):
        nr = DNS_RECORD()
        nr['Type'] = rtype
        nr['Serial'] = serial
        nr['TtlSeconds'] = 180
        nr['Rank'] = 240

        nr['Data'] = DNS_RPC_RECORD_A()
        nr['Data'].fromCanonical(recordaddress)
        return nr

    def parse_record_data(record):
        rd = {}
        rtype = None
        address = None
        tstime = None
        record_data = None
        rtype = RECORD_TYPE_MAPPING.get(record['Type'])

        if not rtype:
            rd['RecordType'] = "Unsupported"
            return

        rd['RecordType'] = rtype

        if record['Type'] == 0:
            tstime = DNS_RPC_RECORD_TS(record['Data']).toDatetime()
            rd['tstime'] = tstime
        if record['Type'] == 1:
            address = DNS_RPC_RECORD_A(record['Data']).formatCanonical()
            rd['Address'] = address
        if record['Type'] == 2 or record['Type'] == 5:
            address = DNS_RPC_RECORD_NODE_NAME(record['Data'])['nameNode'].toFqdn()
            rd['Address'] = address
        if record['Type'] == 33:
            record_data = DNS_RPC_RECORD_SRV(record['Data'])
            rd['Priority'] = record_data['wPriority']
            rd['Weight'] = record_data['wWeight']
            rd['Port'] = record_data['wPort']
            rd['Name'] = record_data['nameTarget'].toFqdn()
        if record['Type'] == 6:
            record_data = DNS_RPC_RECORD_SOA(record['Data'])
            rd['Serial'] = record_data['dwSerialNo']
            rd['Refresh'] = record_data['dwRefresh']
            rd['Retry'] = record_data['dwRetry']
            rd['Expire'] = record_data['dwExpire']
            rd['Minimum'] = record_data['dwMinimumTtl']
            rd['Primary Server'] = record_data['namePrimaryServer'].toFqdn()
            rd['Zone Admin Email'] = record_data['zoneAdminEmail'].toFqdn()

        return rd


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    [MS-DNSP] section 2.2.2.2.4.17
    """
    structure = (
        ('ipv6Address', '16s'),
    )

class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

