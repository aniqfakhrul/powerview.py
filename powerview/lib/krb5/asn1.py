#!/usr/bin/env python3

from pyasn1.type import univ, namedtype, tag
from impacket.krb5.asn1 import PrincipalName, Realm, UInt32, KerberosFlags, Checksum, EncryptionKey, KerberosTime, _sequence_component, _sequence_optional_component

class KERB_SUPERSEDED_BY_USER(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_sequence_component('name', 0, PrincipalName()),
		_sequence_optional_component('userRealm', 1, Realm()),
	)

class S4UUserID(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_sequence_component('nonce', 0,  UInt32()),
		_sequence_component('cname', 1, PrincipalName()),
		_sequence_optional_component('crealm', 2, Realm()),
		_sequence_optional_component('subject-certificate', 3, univ.OctetString()),
		_sequence_optional_component('options', 4, KerberosFlags())
	)

class PA_S4U_X509_USER(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('user-id', S4UUserID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
		namedtype.NamedType('checksum', Checksum().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))))

class PA_DMSA_KEY_PACKAGE(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_sequence_component("current-keys", 0, univ.SequenceOf(componentType=EncryptionKey())),
		_sequence_optional_component("previous-keys", 1, univ.SequenceOf(componentType=EncryptionKey())),
		_sequence_component("effective-time", 2, KerberosTime()),
		_sequence_optional_component("reserved", 3, univ.OctetString()),
		_sequence_component("expiration-time", 4, KerberosTime())
		)