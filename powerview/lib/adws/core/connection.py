from .. import RESOURCE, RESOURCE_FACTORY, ENUMERATION, ACCOUNT_MANAGEMENT, TOPOLOGY_MANAGEMENT
from ..operation.search import search_operation, handle_str_to_xml, handle_enum_ctx, parse_adws_pull_response
from ..nns import NNS
from ..nmf import NMFConnection
from ..templates import NAMESPACES

from ldap3.utils.dn import safe_dn
from ldap3 import ALL_ATTRIBUTES, NO_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, NTLM, BASE, LEVEL, SUBTREE
from ldap3.protocol.rfc2696 import paged_search_control

import logging
import socket

class Connection(object):
    def __init__(self, server, user, password, domain, lmhash, nthash, raise_exceptions=False, authentication=NTLM, check_names=True):
        self.server = server
        self.host = server.host
        self.port = server.port
        self.resource = server.resource
        self.user = user
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.raise_exceptions = raise_exceptions
        self.authentication = authentication
        self.check_names = check_names
    
    def _create_NNS_from_auth(self, sock: socket.socket) -> NNS:
        if self.authentication == NTLM:
            return NNS(
                socket=sock,
                fqdn=self.host,
                domain=self.domain,
                username=self.user,
                password=self.password,
                nt=self.nthash if self.nthash else "",
                lm=self.lmhash if self.lmhash else ""
            )
        raise NotImplementedError

    def refresh_server_info(self):
        logging.debug("Refreshing server info")
        self.server.get_info_from_server(self)

    def search(self,
               search_base,
               search_filter,
               search_scope=SUBTREE,
               attributes=None,
               size_limit=0,
               time_limit=0,
               types_only=False,
               get_operational_attributes=False,
               controls=None,
               paged_size=None,
               paged_criticality=False,
               paged_cookie=None,
               auto_escape=None):
        """
        Perform a search operation on the server.
        """
        if self.check_names and search_base:
            search_base = safe_dn(search_base)

        if not attributes:
            attributes = [NO_ATTRIBUTES]
        elif attributes == ALL_ATTRIBUTES:
            attributes = [ALL_ATTRIBUTES]

        if get_operational_attributes and isinstance(attributes, list):
            attributes.append(ALL_OPERATIONAL_ATTRIBUTES)
        elif get_operational_attributes and isinstance(attributes, tuple):
            attributes += (ALL_OPERATIONAL_ATTRIBUTES, )  # concatenate tuple

        if isinstance(paged_size, int):
            if controls is None:
                controls = []
            else:
                # Copy the controls to prevent modifying the original object
                controls = list(controls)
            controls.append(paged_search_control(paged_criticality, paged_size, paged_cookie))

        # make search operation to the server before pulling the results
        request = search_operation(self.host, search_base, search_filter, search_scope, attributes)
        self.nmf.send(request)
        enumerationResponse = self.nmf.recv()
        et = handle_str_to_xml(enumerationResponse)
        enum_ctx = et.find(".//wsen:EnumerationContext", NAMESPACES).text
        if enum_ctx is None:
            raise ValueError("Enum Context not found in response")

        # now we need to pull the results from the server
        pull_request = handle_enum_ctx(self.host, enum_ctx)
        self.nmf.send(pull_request)
        pull_response = self.nmf.recv()
        results = parse_adws_pull_response(pull_response)
        return results

    def connect(self, resource=None):
        """Connect to the specified ADWS endpoint at the
        Args:
            resource (str): endpoint to connect to <'Resource', 'ResourceFactory',
                'Enumeration', AccountManagement',  'TopologyManagement'>
        """
        server_address: tuple[str, int] = (self.host, self.port)
        resource = ENUMERATION if not resource else self.resource
        logging.debug(f"Connecting to {self.host} for {resource}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_address)
        
        self.nmf = NMFConnection(
            self._create_NNS_from_auth(sock),
            fqdn=self.host,
            port=self.port
        )
        self.nmf.connect(f"Windows/{resource}")
        self.refresh_server_info()
        return self.server, self