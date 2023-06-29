import argparse
import sys
import traceback
import ldap3
import ssl
import ldapdomaindump
import ipaddress
import dns.resolver
from binascii import unhexlify
import os
import json
import logging
from impacket import version
from impacket.examples import logger, utils
from dns import resolver
import struct
from ldap3.utils.conv import escape_filter_chars
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

def get_principal_dc_address(domain, nameserver, dns_tcp=True):
    answer = None

    basequery = f'_ldap._tcp.pdc._msdcs.{domain}'
    dnsresolver = resolver.Resolver(configure=False)
    
    if nameserver:
        logging.debug(f'Querying domain controller information from DNS server {nameserver}')
        dnsresolver.nameservers = [nameserver]
    else:
        logging.debug(f'No nameserver provided, using host\'s resolver to resolve {domain}')

    dnsresolver.lifetime = float(3)

    try:
        q = dnsresolver.query(basequery, 'SRV', tcp=dns_tcp)

        if str(q.qname).lower().startswith('_ldap._tcp.pdc._msdcs'):
            ad_domain = str(q.qname).lower()[len(basequery):].strip('.')
            logging.debug('Found AD domain: %s' % ad_domain)

        for r in q:
            dc = str(r.target).rstrip('.')
        #resolve ip for principal dc
        answer = resolve_domain(dc, nameserver)
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
        q = dnsresolver.query(basequery.replace('pdc','dc'), 'SRV', tcp=dns_tcp)
        for r in q:
            dc = str(r.target).rstrip('.')
            logging.debug('Found AD Domain: %s' % dc)
        answer = resolve_domain(dc,nameserver)
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
    domain, username, password, address = utils.parse_target(args.target)

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.auth_aes_key is None:
        from getpass import getpass
        logging.info("No credentials supplied, supply password")
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


def host2ip(hostname, nameserver, dns_timeout=10, dns_tcp=True):
    hostname = str(hostname)
    if hostname in list(STORED_ADDR.keys()):
        return STORED_ADDR[hostname]

    dnsresolver = resolver.Resolver()
    if nameserver:
        logging.debug(f"Querying {hostname} from DNS server {nameserver}")
        dnsresolver.nameservers = [nameserver]
    else:
        logging.debug(f"No nameserver provided, using host's resolver to resolve {hostname}")

    dnsresolver.lifetime = float(dns_timeout)
    try:
        q = dnsresolver.query(hostname, 'A', tcp=dns_tcp)
        addr = None
        for r in q:
            if addr:
                break
            addr = r.address
        STORED_ADDR[hostname] = addr
        return addr
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
            host_ip = host2ip(str(host['dNSHostName']), options.nameserver, 3, True)
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
