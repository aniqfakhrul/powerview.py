import argparse
import logging
import sys
import traceback
import ldap3
import ssl
import ldapdomaindump
from binascii import unhexlify
import os
import json
from impacket import version
from impacket.examples import logger, utils
from dns import resolver
from ldap3.utils.conv import escape_filter_chars

from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal

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
    return s.getServerName()


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
        hashes = ("aad3b435b51404eeaad3b435b51404ee:".upper() + args.hashes.split(":")[1]).upper()
        lmhash, nthash = hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, lmhash, nthash

def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', auth_aes_key='', kdcHost=None,
                         TGT=None, TGS=None, useCache=False):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string auth_aes_key: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
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
                logging.debug('Domain retrieved from CCache: %s' % domain)

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
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                    auth_aes_key, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
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

def init_ldap_connection(target, no_tls, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    if not no_tls:
        use_ssl = False
        port = 389
    else:
        use_ssl = True
        port = 636
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl)
    if args.use_kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.auth_aes_key, kdcHost=args.dc_ip,useCache=args.no_pass)
    elif args.hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(args, domain, username, password, lmhash, nthash):
    if args.use_kerberos:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain

    if args.use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, args, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, args, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, args, domain, username, password, lmhash, nthash)


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
        dnsresolver.nameservers = [nameserver]
    dnsresolver.lifetime = float(dns_timeout)
    try:
        q = dnsresolver.query(hostname, 'A', tcp=dns_tcp)
        for r in q:
            addr = r.address
        return addr
    except Exception as e:
        logging.error("Resolved Failed: %s" % e)
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

class LDAPRequester():
    def __init__(self, domain_controller, domain=str(), user=(), password=str(),
                 lmhash=str(), nthash=str(), do_kerberos=False, do_tls=False):
        self._domain_controller = domain_controller
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._do_kerberos = do_kerberos
        self._do_tls = do_tls
        self._queried_domain = None
        self._ads_path = None
        self._ads_prefix = None
        self._ldap_connection = None
        self._base_dn = None

        logger = logging.getLogger('pywerview_main_logger.LDAPRequester')
        self._logger = logger

    def _get_netfqdn(self):
        try:
            smb = SMBConnection(self._domain_controller, self._domain_controller)
        except socket.error:
            self._logger.warning('Socket error when opening the SMB connection')
            return str()

        self._logger.debug('SMB loging parameters : user = {0}  / password = {1} / domain = {2} '
                           '/ LM hash = {3} / NT hash = {4}'.format(self._user, self._password,
                                                                    self._domain, self._lmhash,
                                                                    self._nthash))

        smb.login(self._user, self._password, domain=self._domain,
                lmhash=self._lmhash, nthash=self._nthash)
        fqdn = smb.getServerDNSDomainName()
        smb.logoff()

        return fqdn

    def _patch_spn(self, creds, principal):
        self._logger.debug('Patching principal to {}'.format(principal))

        from pyasn1.codec.der import decoder, encoder
        from impacket.krb5.asn1 import TGS_REP, Ticket

        # Code is ~~based on~~ stolen from https://github.com/SecureAuthCorp/impacket/pull/1256
        tgs = creds.toTGS(principal)
        decoded_st = decoder.decode(tgs['KDC_REP'], asn1Spec=TGS_REP())[0]
        decoded_st['ticket']['sname']['name-string'][0] = 'ldap'
        decoded_st['ticket']['sname']['name-string'][1] = self._domain_controller.lower()
        decoded_st['ticket']['realm'] = self._queried_domain.upper()

        new_creds = Credential(data=creds.getData())
        new_creds.ticket = CountedOctetString()
        new_creds.ticket['data'] = encoder.encode(decoded_st['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        new_creds.ticket['length'] = len(new_creds.ticket['data'])
        new_creds['server'].fromPrincipal(Principal(principal, type=constants.PrincipalNameType.NT_PRINCIPAL.value))

        return new_creds

    def _create_ldap_connection(self, queried_domain=str(), ads_path=str(),
                                ads_prefix=str()):
        if not self._domain:
            if self._do_kerberos:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
                self._domain = ccache.principal.realm['data'].decode('utf-8')
            else:
                try:
                    self._domain = self._get_netfqdn()
                except SessionError as e:
                    self._logger.critical(e)
                    sys.exit(-1)

        if not queried_domain:
            if self._do_kerberos:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
                queried_domain = ccache.principal.realm['data'].decode('utf-8')
            else:
                try:
                    queried_domain = self._get_netfqdn()
                except SessionError as e:
                    self._logger.critical(e)
                    sys.exit(-1)
        self._queried_domain = queried_domain

        base_dn = str()

        if ads_prefix:
            self._ads_prefix = ads_prefix
            base_dn = '{},'.format(self._ads_prefix)

        if ads_path:
            # TODO: manage ADS path starting with 'GC://'
            if ads_path.upper().startswith('LDAP://'):
                ads_path = ads_path[7:]
            self._ads_path = ads_path
            base_dn += self._ads_path
        else:
            base_dn += ','.join('dc={}'.format(x) for x in self._queried_domain.split('.'))

        # base_dn is no longer used within `_create_ldap_connection()`, but I don't want to break
        # the function call. So we store it in an attriute and use it in `_ldap_search()`
        self._base_dn = base_dn

        # Format the username and the domain
        # ldap3 seems not compatible with USER@DOMAIN format
        if self._do_kerberos:
            user = '{}@{}'.format(self._user, self._domain.upper())
        else:
            user = '{}\\{}'.format(self._domain, self._user)

        # Call custom formatters for several AD attributes
        formatter = {'userAccountControl': fmt.format_useraccountcontrol,
                'trustType': fmt.format_trusttype,
                'trustDirection': fmt.format_trustdirection,
                'trustAttributes': fmt.format_trustattributes,
                'msDS-MaximumPasswordAge': format_ad_timedelta,
                'msDS-MinimumPasswordAge': format_ad_timedelta,
                'msDS-LockoutDuration': format_ad_timedelta,
                'msDS-LockoutObservationWindow': format_ad_timedelta,
                'msDS-GroupMSAMembership': fmt.format_groupmsamembership,
                'msDS-ManagedPassword': fmt.format_managedpassword}

        if self._do_tls:
            ldap_scheme = 'ldaps'
            self._logger.debug('LDAPS connection forced')
        else:
            ldap_scheme = 'ldap'
        ldap_server = ldap3.Server('{}://{}'.format(ldap_scheme, self._domain_controller), formatter=formatter)
        ldap_connection_kwargs = {'user': user, 'raise_exceptions': True}

        # We build the authentication arguments depending on auth mode
        if self._do_kerberos:
            self._logger.debug('LDAP authentication with Keberos')
            ldap_connection_kwargs['authentication'] = ldap3.SASL
            ldap_connection_kwargs['sasl_mechanism'] = ldap3.KERBEROS

            # Verifying if we have the correct TGS/TGT to interrogate the LDAP server
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            principal = 'ldap/{}@{}'.format(self._domain_controller.lower(), self._queried_domain.upper())

            # We look for the TGS with the right SPN
            creds = ccache.getCredential(principal, anySPN=False)
            if creds:
                self._logger.debug('TGS found in KRB5CCNAME file')
                if creds['server'].prettyPrint().lower() != creds['server'].prettyPrint():
                    self._logger.debug('SPN not in lowercase, patching SPN')
                    new_creds = self._patch_spn(creds, principal)
                    # We build a new CCache with the new ticket
                    ccache.credentials.append(new_creds)
                    temp_ccache = tempfile.NamedTemporaryFile()
                    ccache.saveFile(temp_ccache.name)
                    cred_store = {'ccache': 'FILE:{}'.format(temp_ccache.name)}
                else:
                    cred_store = dict()
            else:
                self._logger.debug('TGS not found in KRB5CCNAME, looking for '
                        'TGS with alternative SPN')
                # If we don't find it, we search for any SPN
                creds = ccache.getCredential(principal, anySPN=True)
                if creds:
                    # If we find one, we build a custom TGS
                    self._logger.debug('Alternative TGS found, patching SPN')
                    new_creds = self._patch_spn(creds, principal)
                    # We build a new CCache with the new ticket
                    ccache.credentials.append(new_creds)
                    temp_ccache = tempfile.NamedTemporaryFile()
                    ccache.saveFile(temp_ccache.name)
                    cred_store = {'ccache': 'FILE:{}'.format(temp_ccache.name)}
                else:
                    # If we don't find any, we hope for the best (TGT in cache)
                    self._logger.debug('Alternative TGS not found, using KRB5CCNAME as is '
                            'while hoping it contains a TGT')
                    cred_store = dict()
            ldap_connection_kwargs['cred_store'] = cred_store
            self._logger.debug('LDAP binding parameters: server = {0} / user = {1} '
                   '/ Kerberos auth'.format(self._domain_controller, user))
        else:
            self._logger.debug('LDAP authentication with NTLM')
            ldap_connection_kwargs['authentication'] = ldap3.NTLM
            if self._lmhash and self._nthash:
                ldap_connection_kwargs['password'] = '{}:{}'.format(self._lmhash, self._nthash)
                self._logger.debug('LDAP binding parameters: server = {0} / user = {1} '
                   '/ hash = {2}'.format(self._domain_controller, user, ldap_connection_kwargs['password']))
            else:
                ldap_connection_kwargs['password'] = self._password
                self._logger.debug('LDAP binding parameters: server = {0} / user = {1} '
                   '/ password = {2}'.format(self._domain_controller, user, ldap_connection_kwargs['password']))

        try:
            ldap_connection = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
            try:
                ldap_connection.bind()
            except ldap3.core.exceptions.LDAPSocketOpenError as e:
                self._logger.critical(e)
                if self._do_tls:
                    self._logger.critical('TLS negociation failed, this error is mostly due to your host '
                                          'not supporting SHA1 as signing algorithm for certificates')
                sys.exit(-1)
        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult:
            # We need to try TLS
            self._logger.warning('Server returns LDAPStrongerAuthRequiredResult, falling back to LDAPS')
            ldap_server = ldap3.Server('ldaps://{}'.format(self._domain_controller), formatter=formatter)
            ldap_connection = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
            try:
                ldap_connection.bind()
            except ldap3.core.exceptions.LDAPSocketOpenError as e:
                self._logger.critical(e)
                self._logger.critical('TLS negociation failed, this error is mostly due to your host '
                                      'not supporting SHA1 as signing algorithm for certificates')
                sys.exit(-1)

        self._ldap_connection = ldap_connection

    def _ldap_search(self, search_filter, class_result, attributes=list(), controls=list()):
        results = list()

        # if no attribute name specified, we return all attributes
        if not attributes:
            attributes =  ldap3.ALL_ATTRIBUTES

        self._logger.debug('search_base = {0} / search_filter = {1} / attributes = {2}'.format(self._base_dn,
                                                                                               search_filter,
                                                                                               attributes))

        # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
        search_results=self._ldap_connection.extend.standard.paged_search(search_base=self._base_dn,
                search_filter=search_filter, attributes=attributes,
                controls=controls, paged_size=1000, generator=True)

        try:
            # Skip searchResRef
            for result in search_results:
                if result['type'] != 'searchResEntry':
                    continue
                results.append(class_result(result['attributes']))

        except ldap3.core.exceptions.LDAPAttributeError as e:
            self._logger.critical(e)
            sys.exit(-1)

        if not results:
            self._logger.debug('Query returned an empty result')

        return results

    @staticmethod
    def _ldap_connection_init(f):
        def wrapper(*args, **kwargs):
            instance = args[0]
            queried_domain = kwargs.get('queried_domain', None)
            ads_path = kwargs.get('ads_path', None)
            ads_prefix = kwargs.get('ads_prefix', None)
            if (not instance._ldap_connection) or \
               (queried_domain != instance._queried_domain) or \
               (ads_path != instance._ads_path) or \
               (ads_prefix != instance._ads_prefix):
                if instance._ldap_connection:
                    instance._ldap_connection.unbind()
                instance._create_ldap_connection(queried_domain=queried_domain,
                                                 ads_path=ads_path, ads_prefix=ads_prefix)
            return f(*args, **kwargs)
        return wrapper

    def __enter__(self):
        self._create_ldap_connection()
        return self

    def __exit__(self, type, value, traceback):
        try:
            self._ldap_connection.unbind()
        except AttributeError:
            self._logger.warning('Error when unbinding')
            pass
        self._ldap_connection = None

class RPCRequester():
    def __init__(self, target_computer, domain=str(), user=(), password=str(),
                 lmhash=str(), nthash=str(), do_kerberos=False):
        self._target_computer = target_computer
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._do_kerberos = do_kerberos
        self._pipe = None
        self._rpc_connection = None
        self._dcom = None
        self._wmi_connection = None

        logger = logging.getLogger('pywerview_main_logger.RPCRequester')
        self._logger = logger

    def _create_rpc_connection(self, pipe):
        # Here we build the DCE/RPC connection
        self._pipe = pipe

        binding_strings = dict()
        binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
        binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
        binding_strings['samr'] = samr.MSRPC_UUID_SAMR
        binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
        binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

        # TODO: try to fallback to TCP/139 if tcp/445 is closed
        if self._pipe == r'\drsuapi':
            string_binding = epm.hept_map(self._target_computer, drsuapi.MSRPC_UUID_DRSUAPI,
                                          protocol='ncacn_ip_tcp')
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(username=self._user, password=self._password,
                                         domain=self._domain, lmhash=self._lmhash,
                                         nthash=self._nthash)
        else:
            rpctransport = transport.SMBTransport(self._target_computer, 445, self._pipe,
                                                  username=self._user, password=self._password,
                                                  domain=self._domain, lmhash=self._lmhash,
                                                  nthash=self._nthash, doKerberos=self._do_kerberos)

        rpctransport.set_connect_timeout(10)
        dce = rpctransport.get_dce_rpc()

        if self._pipe == r'\drsuapi':
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
        except Exception as e:
            self._logger.critical('Error when creating RPC connection')
            self._logger.critical(e)
            self._rpc_connection = None
        else:
            dce.bind(binding_strings[self._pipe[1:]])
            self._rpc_connection = dce

    def _create_wmi_connection(self, namespace='root\\cimv2'):
        try:
            self._dcom = DCOMConnection(self._target_computer, self._user, self._password,
                                        self._domain, self._lmhash, self._nthash, doKerberos=self._do_kerberos)
        except Exception as e:
            self._logger.critical('Error when creating WMI connection')
            self._logger.critical(e)
            self._dcom = None
        else:
            i_interface = self._dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                                        wmi.IID_IWbemLevel1Login)
            i_wbem_level1_login = wmi.IWbemLevel1Login(i_interface)
            self._wmi_connection = i_wbem_level1_login.NTLMLogin(ntpath.join('\\\\{}\\'.format(self._target_computer), namespace),
                                                                 NULL, NULL)

    @staticmethod
    def _rpc_connection_init(pipe=r'\srvsvc'):
        def decorator(f):
            def wrapper(*args, **kwargs):
                instance = args[0]
                if (not instance._rpc_connection) or (pipe != instance._pipe):
                    if instance._rpc_connection:
                        instance._rpc_connection.disconnect()
                    instance._create_rpc_connection(pipe=pipe)
                if instance._rpc_connection is None:
                    return None
                return f(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def _wmi_connection_init():
        def decorator(f):
            def wrapper(*args, **kwargs):
                instance = args[0]
                if not instance._wmi_connection:
                    instance._create_wmi_connection()
                if instance._dcom is None:
                    return None
                return f(*args, **kwargs)
            return wrapper
        return decorator

    def __enter__(self):
        # Picked because it's the most used by the net* functions
        self._create_rpc_connection(r'\srvsvc')
        return self

    def __exit__(self, type, value, traceback):
        try:
            self._rpc_connection.disconnect()
        except AttributeError:
            pass
        self._rpc_connection = None

class LDAPRPCRequester(LDAPRequester, RPCRequester):
    def __init__(self, target_computer, domain=str(), user=(), password=str(),
                 lmhash=str(), nthash=str(), do_kerberos=False, do_tls=False,
                 domain_controller=str()):
        # If no domain controller was given, we assume that the user wants to
        # target a domain controller to perform LDAP requests against
        if not domain_controller:
            domain_controller = target_computer
        LDAPRequester.__init__(self, domain_controller, domain, user, password,
                               lmhash, nthash, do_kerberos, do_tls)
        RPCRequester.__init__(self, target_computer, domain, user, password,
                               lmhash, nthash, do_kerberos)

        logger = logging.getLogger('pywerview_main_logger.LDAPRPCRequester')
        self._logger = logger

    def __enter__(self):
        try:
            LDAPRequester.__enter__(self)
        except (socket.error, IndexError):
            pass
        # This should work every time
        RPCRequester.__enter__(self)

        return self

    def __exit__(self, type, value, traceback):
        LDAPRequester.__exit__(self, type, value, traceback)
        RPCRequester.__exit__(self, type, value, traceback)
