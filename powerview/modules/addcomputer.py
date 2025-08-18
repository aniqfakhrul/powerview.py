#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will add a computer account to the domain and set its password.
#   Allows to use SAMR over SMB (this way is used by modern Windows computer when
#   adding machines through the GUI) and LDAPS.
#   Plain LDAP is not supported, as it doesn't allow setting the password.
#
# Author:
#   JaGoTu (@jagotu)
#
# Reference for:
#   SMB, SAMR, LDAP
#
# ToDo:
#   [ ]: Complete the process of joining a client computer to a domain via the SAMR protocol
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

import ldap3
import argparse
import logging
import sys
import string
import random
import ssl
from binascii import unhexlify

from powerview.utils.helpers import is_valid_dn

class ADDCOMPUTER:
    def __init__(self, username=None, password=None, domain=None, cmdLineOptions=None, computer_name=None, computer_pass=None, no_password=False, base_dn=None, ldap_session=None):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__hashes = cmdLineOptions.hashes
        self.__aesKey = cmdLineOptions.auth_aes_key
        self.__doKerberos = cmdLineOptions.use_kerberos
        self.__TGT = cmdLineOptions.TGT
        self.__TGS = cmdLineOptions.TGS
        self.__target = cmdLineOptions.dc_host
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__computerName = computer_name
        self.__computerPassword = computer_pass
        self.__noPassword = no_password
        self.__method = cmdLineOptions.method
        self.__port = None
        self.__domainNetbios = None
        self.__noAdd = False
        self.__delete = cmdLineOptions.delete
        self.__targetIp = cmdLineOptions.dc_ip
        self.__baseDN = None
        self.__computerGroup = None
        self.__ldapSession = ldap_session
        if self.__targetIp is not None:
            self.__kdcHost = self.__targetIp

        if self.__method not in ['SAMR', 'LDAPS']:
            raise ValueError("Unsupported method %s" % self.__method)

        if self.__doKerberos and cmdLineOptions.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use -dc-host.")

        if self.__method == 'LDAPS' and not '.' in self.__domain:
                logging.warning('\'%s\' doesn\'t look like a FQDN. Generating baseDN will probably fail.' % self.__domain)

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        if self.__computerName is None:
            if self.__noAdd:
                raise ValueError("You have to provide a computer name when using -no-add.")
            elif self.__delete:
                raise ValueError("You have to provide a computer name when using -delete.")
        else:
            if self.__computerName[-1] != '$' and not is_valid_dn(self.__computerName):
                self.__computerName += '$'

        if self.__computerPassword is None and not self.__noPassword:
            self.__computerPassword = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

        if self.__target is None:
            if not '.' in self.__domain:
                logging.warning('No DC host set and \'%s\' doesn\'t look like a FQDN. DNS resolution of short names will probably fail.' % self.__domain)
            self.__target = self.__domain

        if self.__port is None:
            if self.__method == 'SAMR':
                self.__port = 445
            elif self.__method == 'LDAPS':
                self.__port = 636

        if self.__domainNetbios is None:
            self.__domainNetbios = self.__domain

        self.__baseDN = base_dn
        self.__computerGroup = self.__baseDN

    def run_samr(self):
        if self.__targetIp is not None:
            stringBinding = epm.hept_map(self.__targetIp, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        else:
            stringBinding = epm.hept_map(self.__target, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.__port)

        if self.__targetIp is not None:
            rpctransport.setRemoteHost(self.__targetIp)
            rpctransport.setRemoteName(self.__target)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey, TGT=self.__TGT, TGS=self.__TGS)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.doSAMRAdd(rpctransport)

    def run_ldaps(self):
        if not self.__ldapSession:
            raise Exception("No ldap_session. Exiting")
        
        ldapConn = self.__ldapSession

        if self.__noAdd or self.__delete:
            if not self.LDAPComputerExists(ldapConn, self.__computerName):
                raise Exception("Account %s not found in %s!" % (self.__computerName, self.__baseDN))

            computer = self.LDAPGetComputer(ldapConn, self.__computerName)

            if self.__delete:
                res = ldapConn.delete(computer.entry_dn)
                message = "delete"
            else:
                res = ldapConn.modify(computer.entry_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, ['"{}"'.format(self.__computerPassword).encode('utf-16-le')])]})
                message = "set password for"


            if not res:
                if ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                    raise Exception("User %s doesn't have right to %s %s!" % (self.__username, message, self.__computerName))
                else:
                    raise Exception(str(ldapConn.result))
            else:
                if self.__noAdd:
                    logging.info("Succesfully set password of %s to %s." % (self.__computerName, self.__computerPassword))
                else:
                    logging.info("Succesfully deleted %s." % self.__computerName)

        else:
            if self.__computerName is not None:
                if self.LDAPComputerExists(ldapConn, self.__computerName):
                    raise Exception("Account %s already exists! If you just want to set a password, use -no-add." % self.__computerName)
            else:
                while True:
                    self.__computerName = self.generateComputerName()
                    if not self.LDAPComputerExists(ldapConn, self.__computerName):
                        break


            computerHostname = self.__computerName[:-1]
            computerDn = ('CN=%s,%s' % (computerHostname, self.__computerGroup))

            # Default computer SPNs
            spns = [
                'HOST/%s' % computerHostname,
                'HOST/%s.%s' % (computerHostname, self.__domain),
                'RestrictedKrbHost/%s' % computerHostname,
                'RestrictedKrbHost/%s.%s' % (computerHostname, self.__domain),
            ]
            uac_value = 0x1000 | (0x20 if self.__noPassword else 0)
            ucd = {
                'dnsHostName': '%s.%s' % (computerHostname, self.__domain),
                'userAccountControl': uac_value,
                'servicePrincipalName': spns,
                'sAMAccountName': self.__computerName,
            }
            if not self.__noPassword:
                ucd['unicodePwd'] = ('"%s"' % self.__computerPassword).encode('utf-16-le')
            
            res = ldapConn.add(computerDn, ['top','person','organizationalPerson','user','computer'], ucd)
            if not res:
                if ldapConn.result['result'] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM:
                    error_code = int(ldapConn.result['message'].split(':')[0].strip(), 16)
                    if error_code == 0x216D:
                        raise Exception("User %s machine quota exceeded!" % self.__username)
                    else:
                        raise Exception(str(ldapConn.result))
                elif ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                    raise Exception("User %s doesn't have right to create a machine account!" % self.__username)
                else:
                    raise Exception(str(ldapConn.result))
            else:
                if self.__noPassword:
                    logging.info("Successfully added machine account %s without a password." % (self.__computerName))
                else:
                    logging.info("Successfully added machine account %s with password %s." % (self.__computerName, self.__computerPassword))

    def LDAPComputerExists(self, connection, computerName):
        connection.search(self.__baseDN, '(|(sAMAccountName={computerName})(distinguishedName={computerName}))'.format(computerName=computerName))
        return len(connection.entries) ==1

    def LDAPGetComputer(self, connection, computerName):
        connection.search(self.__baseDN, '(|(sAMAccountName={computerName})(distinguishedName={computerName}))'.format(computerName=computerName))
        return connection.entries[0]

    def LDAP3KerberosLogin(self, connection, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None,
                      TGS=None, useCache=True):
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
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        import datetime

        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS

        if TGT is not None or TGS is not None:
            useCache = False

        targetName = 'ldap/%s' % self.__target
        if useCache:
            domain, user, TGT, TGS = CCache.parseFile(domain, user, targetName)

        # First of all, we need to get a TGT for the user
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                        aesKey, kdcHost)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            serverName = Principal(targetName, type=constants.PrincipalNameType.NT_SRV_INST.value)
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


        request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData())

        # Done with the Kerberos saga, now let's get into LDAP
        # try to open connection if closed
        if connection.closed:
            connection.open(read_server_info=False)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(connection.send('bindRequest', request, None))
        connection.sasl_in_progress = False
        if response[0]['result'] != 0:
            raise Exception(response)

        connection.bound = True

        return True

    def generateComputerName(self):
        return 'DESKTOP-' + (''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + '$')

    def doSAMRAdd(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        servHandle = None
        domainHandle = None
        userHandle = None
        try:
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            samrConnectResponse = samr.hSamrConnect5(dce, '\\\\%s\x00' % self.__target,
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN )
            servHandle = samrConnectResponse['ServerHandle']

            samrEnumResponse = samr.hSamrEnumerateDomainsInSamServer(dce, servHandle)
            domains = samrEnumResponse['Buffer']['Buffer']
            domainsWithoutBuiltin = list(filter(lambda x : x['Name'].lower() != 'builtin', domains))

            if len(domainsWithoutBuiltin) > 1:
                domain = list(filter(lambda x : x['Name'].lower() == self.__domainNetbios, domains))
                if len(domain) != 1:
                    logging.critical("This server provides multiple domains and '%s' isn't one of them.", self.__domainNetbios)
                    logging.critical("Available domain(s):")
                    for domain in domains:
                        logging.error(" * %s" % domain['Name'])
                    logging.critical("Consider using -domain-netbios argument to specify which one you meant.")
                    raise Exception()
                else:
                    selectedDomain = domain[0]['Name']
            else:
                selectedDomain = domainsWithoutBuiltin[0]['Name']

            samrLookupDomainResponse = samr.hSamrLookupDomainInSamServer(dce, servHandle, selectedDomain)
            domainSID = samrLookupDomainResponse['DomainId']

            if logging.getLogger().level == logging.DEBUG:
                logging.info("Opening domain %s..." % selectedDomain)
            samrOpenDomainResponse = samr.hSamrOpenDomain(dce, servHandle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER , domainSID)
            domainHandle = samrOpenDomainResponse['DomainHandle']


            if self.__noAdd or self.__delete:
                try:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000073:
                        if self.options.stack_trace:           
                            raise 
                        else:
                            logging.error('Account %s not found in domain %s!' % (self.__computerName, selectedDomain))
                            return
                    else:
                        if self.options.stack_trace:
                            raise 
                        else:
                            logging.error('Error: Please use --stack-trace to see the full error.')
                            return

                userRID = checkForUser['RelativeIds']['Element'][0]
                if self.__delete:
                    access = samr.DELETE
                    message = "delete"
                else:
                    access = samr.USER_FORCE_PASSWORD_CHANGE
                    message = "set password for"
                try:
                    openUser = samr.hSamrOpenUser(dce, domainHandle, access, userRID)
                    userHandle = openUser['UserHandle']
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        if self.options.stack_trace:
                            logging.error('User %s doesn\'t have right to %s %s!' % (self.__username, message, self.__computerName))
                            raise 
                        else:
                            logging.error('User %s doesn\'t have right to %s %s!' % (self.__username, message, self.__computerName))
                            return
                    else:
                        if self.options.stack_trace:
                            raise 
                        else:
                            logging.error('Error: Please use --stack-trace to see the full error.')
                            return
            else:
                if self.__computerName is not None:
                    try:
                        checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        raise Exception("Account %s already exists! If you just want to set a password, use -no-add." % self.__computerName)
                    except samr.DCERPCSessionError as e:
                        if e.error_code != 0xc0000073:
                            if self.options.stack_trace:
                                raise
                            else:
                                logging.error('Error: Please use --stack-trace to see the full error.')
                                return
                else:
                    foundUnused = False
                    while not foundUnused:
                        self.__computerName = self.generateComputerName()
                        try:
                            checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        except samr.DCERPCSessionError as e:
                            if e.error_code == 0xc0000073:
                                foundUnused = True
                            else:
                                if self.options.stack_trace:
                                    raise
                                else:
                                    logging.error('Error: Please use --stack-trace to see the full error.')
                                    return

                try:
                    createUser = samr.hSamrCreateUser2InDomain(dce, domainHandle, self.__computerName, samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE,)
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        if self.options.stack_trace:
                            raise 
                        else:
                            logging.error('User %s doesn\'t have right to create a machine account!' % self.__username)
                            return
                    elif e.error_code == 0xc00002e7:
                        if self.options.stack_trace:
                            raise 
                        else:
                            logging.error('User %s machine quota exceeded!' % self.__username)
                            return
                    else:
                        raise

                userHandle = createUser['UserHandle']

            if self.__delete:
                samr.hSamrDeleteUser(dce, userHandle)
                logging.info("Successfully deleted %s." % self.__computerName)
                userHandle = None
            else:
                if not self.__noPassword:
                    samr.hSamrSetPasswordInternal4New(dce, userHandle, self.__computerPassword)
                if self.__noAdd:
                    if self.__noPassword:
                        logging.info("Successfully cleared password requirement for %s." % (self.__computerName))
                    else:
                        logging.info("Successfully set password of %s to %s." % (self.__computerName, self.__computerPassword))
                else:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                    userRID = checkForUser['RelativeIds']['Element'][0]
                    openUser = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, userRID)
                    userHandle = openUser['UserHandle']
                    req = samr.SAMPR_USER_INFO_BUFFER()
                    req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
                    uac_value = samr.USER_WORKSTATION_TRUST_ACCOUNT | (0x20 if self.__noPassword else 0)
                    req['Control']['UserAccountControl'] = uac_value
                    samr.hSamrSetInformationUser2(dce, userHandle, req)
                    if self.__noPassword:
                        logging.info("Successfully added machine account %s without a password." % (self.__computerName))
                    else:
                        logging.info("Successfully added machine account %s with password %s." % (self.__computerName, self.__computerPassword))

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()

            logging.critical(str(e))
        finally:
            if userHandle is not None:
                samr.hSamrCloseHandle(dce, userHandle)
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if servHandle is not None:
                samr.hSamrCloseHandle(dce, servHandle)
            dce.disconnect()
