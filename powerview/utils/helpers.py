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

from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket import version
from impacket.dcerpc.v5 import samr, dtypes
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.types import Principal

from impacket.krb5.kerberosv5 import getKerberosTGT

import configparser
import validators

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

def modify_entry(entry, new_attributes=None, remove=None):
    entries = {}
    e = json.loads(entry.entry_to_json())
    j = e['attributes']
    for i in j:
        if i not in remove:
            entries[i] = j[i]

    if new_attributes:
        for attr in new_attributes:
            entries[attr]= new_attributes[attr]

    return entries

def is_valid_fqdn(hostname: str) -> bool:
    if validators.domain(hostname):
        return True
    else:
        return False

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
    logging.debug(f'Querying domain controller information from DNS server {nameserver}')
    try:
        basequery = f'_ldap._tcp.pdc._msdcs.{domain}'
        dnsresolver = resolver.Resolver(configure=False)
        dnsresolver.nameservers = [nameserver]
        dnsresolver.lifetime = float(3)

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

def get_machine_name(args, domain):
    if args.dc_ip is not None:
        s = SMBConnection(args.dc_ip, args.dc_ip)
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
    domain, username, password = utils.parse_credentials(args.account)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

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

    return domain, username, password, lmhash, nthash

def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logger.debug('Domain retrieved from CCache: %s' % domain)

            logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logging.debug('Using TGT from cache')
                else:
                    logging.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logging.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True

def get_user_info(samname, ldap_session, domain_dumper):
    ldap_session.search(domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), 
            attributes=['objectSid','ms-DS-MachineAccountQuota'])
    try:
        et = ldap_session.entries[0]
        js = et.entry_to_json()
        return json.loads(js)
    except IndexError:
        return False


def host2ip(hostname, nameserver,dns_timeout,dns_tcp):
    dnsresolver = resolver.Resolver()
    if nameserver:
        logging.debug(f"Querying from DNS server {nameserver}")
        dnsresolver.nameservers = [nameserver]
    dnsresolver.lifetime = float(dns_timeout)
    try:
        q = dnsresolver.query(hostname, 'A', tcp=dns_tcp)
        for r in q:
            addr = r.address
        return addr
    except resolver.NXDOMAIN as e:
        logging.debug("Resolved Failed: %s" % e)
        return None

def get_dc_host(ldap_session, domain_dumper,options):
    dc_host = {}
    ldap_session.search(domain_dumper.root, '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', 
            attributes=['name','dNSHostName'])
    if len(ldap_session.entries) > 0:
        for host in ldap_session.entries:
            dc_host[str(host['name'])] = {}
            dc_host[str(host['name'])]['dNSHostName'] = str(host['dNSHostName'])
            host_ip = host2ip(str(host['dNSHostName']), options.dc_ip, 3, True)
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
