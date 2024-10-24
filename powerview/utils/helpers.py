import datetime
import sys
import traceback
import ldap3
import ssl
import ldapdomaindump
import ipaddress
import uuid
import dns.resolver
from binascii import unhexlify
import os
import json
import logging
from impacket import version
from dns import resolver
import struct
from ldap3.utils.conv import escape_filter_chars
from typing import Tuple
import re
import configparser
import validators
import random

from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm
from impacket.smbconnection import SMBConnection
from impacket import version
from impacket.dcerpc.v5 import samr, dtypes
from impacket.examples import logger
from impacket.examples.utils import parse_credentials, parse_target
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT

from powerview.lib.dns import (
    STORED_ADDR
)

def get_uuid(upper=False):
    if upper:
        return str(uuid.uuid4()).upper()
    else:
        return str(uuid.uuid4())

def get_random_hex(length):
    hex_string = '0123456789ABCDEF'
    return ''.join([random.choice(hex_string) for x in range(length)])

def get_random_num(minimum,maximum):
    return random.randint(minimum,maximum)

def dn2rootdn(value):
    return ','.join(re.findall(r"(DC=[\w-]+)", value))

def dn2domain(value):
    return '.'.join(re.findall(r'DC=([\w-]+)',value)).lower()

def escape_filter_chars_except_asterisk(filter_str):
    escaped_chars = ''.join(c if c == '*' else escape_filter_chars(c) for c in filter_str)
    return escaped_chars

def get_user_sids(domain_sid, objectsid):
    user_sids = []
    rid = int(objectsid.split("-")[-1])

    # add domain user group
    user_sids.append(f"{domain_sid}-513")

    # add domain computer group
    user_sids.append(f"{domain_sid}-515")

    # verify object sid
    if rid > 1000:
        user_sids.append(objectsid)

    # Everyone, Authenticated Users, Users
    user_sids += [
        "S-1-1-0",
        "S-1-5-11",
        "S-1-5-32-545"
    ]
    return user_sids

def filetime_to_span(filetime: str) -> int:
    (span,) = struct.unpack("<q", filetime)

    span *= -0.0000001

    return int(span)

def span_to_str(span: int) -> str:
    if (span % 31536000 == 0) and (span // 31536000) >= 1:
        if (span / 31536000) == 1:
            return "1 year"
        return "%i years" % (span // 31536000)
    elif (span % 2592000 == 0) and (span // 2592000) >= 1:
        if (span // 2592000) == 1:
            return "1 month"
        else:
            return "%i months" % (span // 2592000)
    elif (span % 604800 == 0) and (span // 604800) >= 1:
        if (span / 604800) == 1:
            return "1 week"
        else:
            return "%i weeks" % (span // 604800)

    elif (span % 86400 == 0) and (span // 86400) >= 1:
        if (span // 86400) == 1:
            return "1 day"
        else:
            return "%i days" % (span // 86400)
    elif (span % 3600 == 0) and (span / 3600) >= 1:
        if (span // 3600) == 1:
            return "1 hour"
        else:
            return "%i hours" % (span // 3600)
    else:
        return ""

def filetime_to_str(filetime: str) -> str:
    return span_to_str(filetime_to_span(filetime))

def to_pascal_case(snake_str: str) -> str:
    components = snake_str.split("_")
    return "".join(x.title() for x in components)

def is_admin_sid(sid: str):
    return (
        re.match("^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$", sid) is not None
        or sid == "S-1-5-9"
        or sid == "S-1-5-32-544"
    )

def convert_to_json_serializable(obj):
    if isinstance(obj, bytes):
        # Convert bytes to string
        return obj.decode('utf-8')
    elif isinstance(obj, datetime):
        # Convert datetime to string
        return obj.isoformat()
    else:
        return obj

def strip_entry(entry):
    for k,v in entry["attributes"].items():
        # check if its only have 1 index,
        # then break it into string
        if isinstance(v, list):
            if len(v) == 1:
                if k in [
                        "dnsRecord",
                ]:
                    continue
                if not isinstance(v[0], str):
                    continue
                entry["attributes"][k] = v[0]

def from_json_to_entry(entry):
    return json.loads(entry)

def filter_entry(entry, properties):
    new_dict = {}
    ori_list = list(entry.keys())
    for p in properties:
        if p.lower() not in [x.lower() for x in ori_list]:
            continue
        for i in ori_list:
            if p.casefold() == i.casefold():
                new_dict[i] = entry[i]
    return new_dict

def modify_entry(entry, new_attributes=[], remove=[]):
    entries = {}
    if isinstance(entry,ldap3.abstract.entry.Entry):
        entry = json.loads(entry.entry_to_json())
    j = entry['attributes']

    for i in j:
        if i not in remove:
            entries[i] = j[i]

    if new_attributes:
        for attr in new_attributes:
            entries[attr]= new_attributes[attr]

    return {"attributes":entries}

def is_valid_fqdn(hostname: str) -> bool:
    if validators.domain(hostname):
        return True
    else:
        return False

def ini_to_dict(obj):
    d = {}
    try:
        config_string = '[dummy_section]\n' + obj
        t = configparser.ConfigParser(converters={'list': lambda x: [int(i) if i.isnumeric() else i.strip() for i in x.replace("|",",").split(',')]})
        t.read_string(config_string)
    except configparser.ParsingError as e:
        return None
    for k in t['dummy_section'].keys():
        d['attribute'] = k
        #In case the value is a Distinguished Name
        if re.search(r'^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$', t.get('dummy_section', k)):
            d['value'] = t.get('dummy_section', k)
        else:
            d['value'] = t.getlist('dummy_section', k)
    return d

def read_file(path, mode="r"):
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        raise Exception(f"File {path} not found")

    content = None
    with open(path, mode) as f:
        content = f.read()
        f.close()

    return content

def parse_object(obj):
    if '{' not in obj and '}' not in obj:
        logging.error('Error format retrieve, (e.g. {dnsHostName=temppc.contoso.local})')
        return None
    attrs = dict()
    try:
        regex = r'\{(.*?)\}'
        res = re.search(regex,obj)
        dd = res.group(1).replace("'","").replace('"','').split("=")
        attrs['attr'] = dd[0].strip()
        attrs['val'] = dd[1].strip()
        return attrs
    except:
        raise Exception('Error regex parsing')

def parse_inicontent(filecontent=None, filepath=None):
    infobject = []
    infdict = {}
    config = configparser.ConfigParser(allow_no_value=True)
    config.read_string(filecontent)
    if "Group Membership" in list(config.keys()):
        for left, right in config['Group Membership'].items():
            if "memberof" in left:
                infdict['sids'] = left.replace("*","").replace("__memberof","")
                infdict['members'] = ""
                infdict['memberof'] = right.replace("*","")
            elif "members" in left:
                infdict['sids'] = left.replace("*","").replace("__members","")
                infdict['members'] = right.replace("*","")
                infdict['memberof'] = ""
            #infdict = {'sid':left.replace("*","").replace("__memberof",""), 'memberof': right.replace("*","").replace("__members","")}
            infobject.append(infdict.copy())
        return True, infobject
    return False, infobject
    #return sections, comments, keys

def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
    return t

def get_time_string(large_integer):
    time = (large_integer['HighPart'] << 32) + large_integer['LowPart']
    if time == 0 or time == 0x7FFFFFFFFFFFFFFF:
        time = 'Never'
    else:
        time = datetime.datetime.fromtimestamp(getUnixTime(time))
        time = time.strftime("%m/%d/%Y %H:%M:%S %p")
    return time

def list_to_str(_input):
    if isinstance(_input, list):
        _input = ''.join(_input)
    return _input

def is_ipaddress(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def get_principal_dc_address(domain, nameserver=None, dns_tcp=True, use_system_ns=True):
    answer = None

    basequery = f'_ldap._tcp.pdc._msdcs.{domain}'
    dnsresolver = None
    
    if nameserver:
        logging.debug(f'Querying domain controller information from DNS server {nameserver}')
        dnsresolver = resolver.Resolver(configure=False)
        dnsresolver.nameservers = [nameserver]
    else:
        logging.debug(f'No nameserver provided, using system\'s dns to resolve {domain}')
        dnsresolver = resolver.Resolver()

    dnsresolver.lifetime = float(3)

    try:
        q = dnsresolver.resolve(basequery, 'SRV', tcp=dns_tcp)

        if str(q.qname).lower().startswith('_ldap._tcp.pdc._msdcs'):
            ad_domain = str(q.qname).lower().lstrip("_ldap._tcp.pdc._msdcs").rstrip(".")
            logging.debug('Found AD domain: %s' % ad_domain)

        for r in q:
            dc = str(r.target).rstrip('.')
        #resolve ip for principal dc
        answer = host2ip(dc, nameserver, 3, dns_tcp, use_system_ns)
        return answer
    except resolver.NXDOMAIN as e:
        logging.debug(str(e))
        logging.debug("Principal DC not found, querying other record")
        pass
    except dns.resolver.NoAnswer as e:
        logging.debug(str(e))
        pass
    except dns.resolver.LifetimeTimeout as e:
        logging.debug("Domain resolution timed out")
        return

    try:
        logging.debug("Querying all DCs")
        q = dnsresolver.resolve(basequery.replace('pdc','dc'), 'SRV', tcp=dns_tcp)
        for r in q:
            dc = str(r.target).rstrip('.')
            logging.debug('Found AD Domain: %s' % dc)

        answer = host2ip(dc, nameserver, 3, dns_tcp, use_system_ns)
        return answer
    except resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer as e:
        logging.debug(str(e))
        pass
    return answer

def resolve_domain(domain, nameserver):
    answer = None
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        answers = resolver.query(domain, 'A', tcp=True)
        for i in answers:
            answer = i.to_text()
    except dns.resolver.NoNameservers:
        logging.info(f'Records not found')
    except dns.resolver.NoAnswer as e:
        logging.error(str(e))
    return answer

def get_machine_name(domain, args=None):
    if args and args.ldap_address is not None:
        s = SMBConnection(args.ldap_address, args.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    #return s.getServerName()
    return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())


def parse_identity(args):
    #domain, username, password = utils.parse_credentials(args.account)
    domain, username, password, address = parse_target(args.target)

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.auth_aes_key is None:
        if args.pfx is not None:
            pasword = None
        else:
            from getpass import getpass
            password = getpass("Password:")

    if args.auth_aes_key is not None:
        args.k = True

    if args.hashes is not None:
        if ":" not in args.hashes[0] and len(args.hashes) == 32:
            args.hashes = ":"+args.hashes
        hashes = ("aad3b435b51404eeaad3b435b51404ee:".upper() + args.hashes.split(":")[1]).upper()
        lmhash, nthash = hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, lmhash, nthash, address

def get_user_info(samname, ldap_session, domain_dumper):
    ldap_session.search(domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname),
            attributes=['objectSid','ms-DS-MachineAccountQuota'])
    try:
        et = ldap_session.entries[0]
        js = et.entry_to_json()
        return json.loads(js)
    except IndexError:
        return False


def host2ip(hostname, nameserver=None, dns_timeout=10, dns_tcp=True, use_system_ns=True, type=str):
    hostname = str(hostname)
    if hostname in list(STORED_ADDR.keys()):
        return STORED_ADDR[hostname]

    dnsresolver = None
    if nameserver:
        logging.debug(f"Querying {hostname} from DNS server {nameserver}")
        dnsresolver = resolver.Resolver(configure=False)
        dnsresolver.nameservers = [nameserver]
    elif use_system_ns:
        logging.debug(f"Using host's resolver to resolve {hostname}")
        dnsresolver = resolver.Resolver()
    else:
        return hostname

    dnsresolver.lifetime = float(dns_timeout)
    try:
        q = dnsresolver.resolve(hostname, 'A', tcp=dns_tcp)
        addr = []
        ip = None

        for r in q:
            addr.append(r.address)

        if len(addr) == 1:
            STORED_ADDR[hostname] = addr
            ip = addr[0] 
        elif len(addr) > 1 and type == str:
            c_key = 0
            logging.info('We have more than one ip. Please choose one that is reachable')
            cnt = 0
            for name in addr:
                print(f"{cnt}: {name}")
                cnt += 1
            while True:
                try:
                    c_key = int(input(">>> Your choice: "))
                    if c_key in range(len(addr)):
                        break
                except Exception:
                    pass
            ip = addr[c_key]
        elif len(addr) > 1 and type == list:
            return addr
        else:
            logging.error("Error resolving address with unknown error")

        return ip

    except resolver.NXDOMAIN as e:
        logging.debug("Resolved Failed: %s" % e)
        return None
    except dns.exception.Timeout as e:
        logging.debug(str(e))
        return None
    except dns.resolver.NoNameservers as e:
        logging.debug(str(e))
        return None

def get_dc_host(ldap_session, domain_dumper, options):
    dc_host = {}
    ldap_session.search(domain_dumper.root, '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            attributes=['name','dNSHostName'])
    if len(ldap_session.entries) > 0:
        for host in ldap_session.entries:
            dc_host[str(host['name'])] = {}
            dc_host[str(host['name'])]['dNSHostName'] = str(host['dNSHostName'])
            host_ip = host2ip(str(host['dNSHostName']), options.nameserver, 3, True, use_system_ns=options.use_system_nameserver)
            if host_ip:
                dc_host[str(host['name'])]['HostIP'] = host_ip
            else:
                dc_host[str(host['name'])]['HostIP'] = ''
    return dc_host

def get_domain_admins(ldap_session, domain_dumper):
    admins = []
    ldap_session.search(domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars("Domain Admins"),
            attributes=['objectSid'])
    a = ldap_session.entries[0]
    js = a.entry_to_json()
    dn = json.loads(js)['dn']
    search_filter = f"(&(objectClass=person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:={dn}))"

    ldap_session.search(domain_dumper.root, search_filter, attributes=["sAMAccountName"])
    for u in ldap_session.entries:
        admins.append(str(u['sAMAccountName']))

    return admins

# Del computer if we have rights.
def del_added_computer(ldap_session, domain_dumper, domainComputer):
    logging.info("Attempting to del a computer with the name: %s" % domainComputer)
    success = ldap_session.search(domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(domainComputer), attributes=['objectSid'])
    if success is False or len(ldap_session.entries) != 1:
        logging.error("Host {} not found..".format(domainComputer))
        return
    target = ldap_session.entries[0]
    target_dn = target.entry_dn
    ldap_session.delete(target_dn)
    if ldap_session.result['result'] == 0:
        logging.info('Delete computer {} successfully!'.format(domainComputer))
    else:
        logging.critical('Delete computer {} Failed! Maybe the current user does not have permission.'.format(domainComputer))

def cryptPassword(session_key, password):
    try:
        from Cryptodome.Cipher import ARC4
    except Exception:
        LOG.error("Warning: You don't have any crypto installed. You need pycryptodomex")
        LOG.error("See https://pypi.org/project/pycryptodomex/")

    sam_user_pass = samr.SAMPR_USER_PASSWORD()
    encoded_pass = password.encode('utf-16le')
    plen = len(encoded_pass)
    sam_user_pass['Buffer'] = b'A' * (512 - plen) + encoded_pass
    sam_user_pass['Length'] = plen
    pwdBuff = sam_user_pass.getData()

    rc4 = ARC4.new(session_key)
    encBuf = rc4.encrypt(pwdBuff)

    sam_user_pass_enc = samr.SAMPR_ENCRYPTED_USER_PASSWORD()
    sam_user_pass_enc['Buffer'] = encBuf
    return sam_user_pass_enc

class GETTGT:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user= target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__auth_aes_key = None
        self.__options = options
        self.__kdcHost = options.dc_ip
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')
        if options.old_hash:
            self.__password = None
            self.__lmhash, self.__nthash = options.old_pass.split(':')

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__user + '.ccache'))
        from impacket.krb5.ccache import CCache
        ccache = CCache()

        ccache.fromTGT(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__user + '.ccache')

    def run(self):
        userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash), unhexlify(self.__nthash), self.__auth_aes_key,
                                                                self.__kdcHost)
        self.saveTicket(tgt,oldSessionKey)

class IStr(str):
    def __hash__(self):
        return hash(self.lower())
    
    def __eq__(self, other):
        if isinstance(other, str):
            return self.lower() == other.lower()
        return NotImplemented
    
    def __ne__(self, other):
        return not (self == other)
    
    def __lt__(self, other):
        if isinstance(other, str):
            return self.lower() < other.lower()
        return NotImplemented
    
    def __ge__(self, other):
        return not (self < other)
    
    def __gt__(self, other):
        if isinstance(other, str):
            return self.lower() > other.lower()
        return NotImplemented
    
    def __le__(self, other):
        return not (self > other)
    
    def __contains__(self, other: str):
        return other.lower() in self.lower()

class IDict(dict):
    @staticmethod
    def _key(k):
        return IStr(k) if isinstance(k, str) else k
    
    @classmethod
    def fromkeys(cls, keys, val=None):
        dic = cls()
        for i in keys:
            dic[i] = val
        return dic
    
    def __init__(self, *args, **kwargs):
        super(IDict, self).__init__(*args, **kwargs)
        if self.keys():
            for k in list(self.keys()):
                v = super(IDict, self).pop(k)
                self.__setitem__(k, v)
    
    def __contains__(self, key):
        key = IDict._key(key)
        return super(IDict, self).__contains__(key)
    
    def __delitem__(self, key):
        key = IDict._key(key)
        if key in self:
            super(IDict, self).__delitem__(key)
    
    def __getitem__(self, key):
        key = IDict._key(key)
        if key in self:
            return super(IDict, self).__getitem__(key)
    
    def __setitem__(self, key, val):
        key = IDict._key(key)
        super(IDict, self).__setitem__(key, val)
    
    def at(self, i: int):
        if i not in range(len(self)):
            return None
        key = list(self.keys())[i]
        val = list(self.values())[i]
        return (key, val)
    
    def copy(self):
        return IDict(self.items())
    
    def get(self, key, *args, **kwargs):
        key = IDict._key(key)
        if key in self:
            return super(IDict, self).get(key, *args, **kwargs)
        return None
    
    def index(self, key):
        k = IDict._key(key)
        if k not in self:
            return None
        return list(self.keys()).index(k)
    
    def key_at(self, i: int):
        if i not in range(len(self)):
            return None
        k = list(self.keys())[i]
        return k
    
    def multiget(self, keys=None):
        if not keys:
            return None
        return [self.get(i) for i in keys]
    
    def multipop(self, keys):
        if not keys:
            return None
        for i in keys:
            self.pop(i)
    
    def pop(self, key, *args, **kwargs):
        key = IDict._key(key)
        if key in self:
            return super(IDict, self).pop(key, *args, **kwargs)
        return None
    
    def setdefault(self, key, val=None):
        key = IDict._key(key)
        return super(IDict, self).setdefault(key, val)
    
    def update(self, obj=None):
        if not obj:
            return None
        
        if isinstance(obj, dict):
            obj = obj.items()
        
        for key, val in obj:
            key = IDict._key(key)
            super(IDict, self).update({key: val})
    
    def value_at(self, i: int):
        if i not in range(len(self)):
            return None
        return list(self.values())[i]
