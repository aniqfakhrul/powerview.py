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
        self.ldap_session.search(ca_search_base, enroll_filter, attributes=properties)
        return self.ldap_session

    def fetch_enrollment_services(self, properties='*'):
        enroll_filter = "(objectCategory=pKIEnrollmentService)"
        conf_base = "CN=Configuration,{}".format(self.root_dn)

        entries = self.ldap_session.search(enroll_filter,conf_base,attributes=properties)

        return entries
        """
        for item in ldap_results(resp):
            enr = EnrollmentService()
            for attribute in item['attributes']:
                at_type = str(attribute['type'])
                if at_type == "cACertificate":
                    cert_bytes = attribute['vals'][0].asOctets()
                    enr.cert = load_x509_certificate(cert_bytes, cert_format="der")
                elif at_type == "name":
                    enr.name = str(attribute['vals'][0])
                elif at_type == "dNSHostName":
                    enr.dnsname = str(attribute['vals'][0])
                elif at_type == "certificateTemplates":
                    enr.templates = [str(v) for v in attribute['vals']]
        """
