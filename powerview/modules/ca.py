#!/usr/bin/env python3
import logging

class CAEnum:
    def __init__(self, ldap_session, root_dn):
        self.ldap_session = ldap_session
        self.root_dn = root_dn

    def fetch_root_ca(self, properties='*'):
        enroll_filter = "(objectclass=certificationAuthority)"
        ca_search_base = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        logging.debug(f'LDAP Base: {ca_search_base}')
        logging.debug(f'LDAP Filter: {enroll_filter}')
        self.ldap_session.search(ca_search_base, enroll_filter,attributes='*')
        return self.ldap_session.entries

    def fetch_enrollment_services(self, properties='*'):
        enroll_filter = "(objectCategory=pKIEnrollmentService)"
        conf_base = "CN=Configuration,{}".format(self.root_dn)

        self.ldap_session.search(conf_base,enroll_filter,attributes=properties)

        return self.ldap_session.entries
