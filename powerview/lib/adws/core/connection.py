from .. import OPERATIONAL_ATTRIBUTES, RESOURCE, RESOURCE_FACTORY, ENUMERATION, ACCOUNT_MANAGEMENT, TOPOLOGY_MANAGEMENT, COMMON_ATTRIBUTES
from ..operation.search import search_operation, handle_str_to_xml, handle_enum_ctx, parse_adws_pull_response, xml_to_dict
from ..operation.modify import modify_operation
from ..nns import NNS
from ..nmf import NMFConnection
from ..templates import NAMESPACES
from ..error import ADWSError

from ldap3.utils.dn import safe_dn
from ldap3 import ALL_ATTRIBUTES, NO_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, NTLM, BASE, LEVEL, SUBTREE, STRING_TYPES, get_config_parameter, SEQUENCE_TYPES, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT
from ldap3.protocol.rfc2696 import paged_search_control
from ldap3.core.exceptions import LDAPChangeError, LDAPAttributeError

import logging
import socket

class Connection(object):
    def __init__(self, server, user, password, domain, lmhash, nthash, raise_exceptions=False, authentication=NTLM, check_names=True, auto_encode=True):
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
        self.auto_encode = auto_encode

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

    def send_and_recv(self, request):
        self.nmf.send(request)
        response = self.nmf.recv()
        return response

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
        if self.resource != ENUMERATION:
            logging.debug("Search is only supported for the \"Enumeration\" resource, reconnecting to the server")
            self.reconnect(ENUMERATION)

        conf_attributes_excluded_from_check = [v.lower() for v in get_config_parameter('ATTRIBUTES_EXCLUDED_FROM_CHECK')]

        if self.check_names and search_base:
            search_base = safe_dn(search_base)

        if not attributes:
            attributes = [NO_ATTRIBUTES]
        elif attributes == ALL_ATTRIBUTES:
            attributes = [ALL_ATTRIBUTES]

        if isinstance(attributes, STRING_TYPES):
            attributes = [attributes]

        if get_operational_attributes and isinstance(attributes, list):
            attributes.append(ALL_OPERATIONAL_ATTRIBUTES)
        elif get_operational_attributes and isinstance(attributes, tuple):
            attributes += (ALL_OPERATIONAL_ATTRIBUTES, )  # concatenate tuple

        if isinstance(paged_size, int):
            if controls is None:
                controls = []
            else:
                controls = list(controls)
            controls.append(paged_search_control(paged_criticality, paged_size, paged_cookie))

        if self.server and self.server.schema and self.check_names:
            for attribute_name in attributes:
                if ';' in attribute_name:  # remove tags
                    attribute_name_to_check = attribute_name.split(';')[0]
                else:
                    attribute_name_to_check = attribute_name
                if (
                    self.server.schema
                    and attribute_name_to_check.lower() not in conf_attributes_excluded_from_check
                    and attribute_name_to_check not in self.server.schema.attribute_types
                    and attribute_name_to_check not in OPERATIONAL_ATTRIBUTES
                ):
                    self.last_error = 'invalid attribute type ' + attribute_name_to_check
                    if self.raise_exceptions:
                        raise LDAPAttributeError(self.last_error)

        try:
            # make search operation to the server before pulling the results
            request = search_operation(self.host, search_base, search_filter, search_scope, attributes)
            response = self.send_and_recv(request)
            et = handle_str_to_xml(response)
            if not et:
                raise ValueError("was unable to parse xml from the server response")

            enum_ctx = et.find(".//wsen:EnumerationContext", NAMESPACES).text
            if enum_ctx is None:
                raise ValueError("Enum Context not found in response")

            # now we need to pull the results from the server
            pull_request = handle_enum_ctx(self.host, enum_ctx)
            response = self.send_and_recv(pull_request)
            results = parse_adws_pull_response(response)
            return results
        except ADWSError as e:
            if "size limit was exceeded" in str(e).lower() and attributes and isinstance(attributes, list):
                logging.warning("Size limit was exceeded, trying default attributes")
                attributes = COMMON_ATTRIBUTES
                return self.search(search_base, search_filter, search_scope, attributes, size_limit, time_limit, types_only, get_operational_attributes, controls, paged_size, paged_criticality, paged_cookie, auto_escape)
            else:
                raise

    def modify(self,
               dn,
               changes,
               controls=None):
        """
        Modify attributes of entry

        - changes is a dictionary in the form {'attribute1': change), 'attribute2': [change, change, ...], ...}
        - change is (operation, [value1, value2, ...])
        - operation is 0 (MODIFY_ADD), 1 (MODIFY_DELETE), 2 (MODIFY_REPLACE), 3 (MODIFY_INCREMENT)
        """
        if self.resource != RESOURCE:
            logging.debug("Modify is only supported for the \"Resource\" resource, reconnecting to the server")
            self.reconnect(RESOURCE)

        conf_attributes_excluded_from_check = [v.lower() for v in get_config_parameter('ATTRIBUTES_EXCLUDED_FROM_CHECK')]
        
        if self.check_names:
            dn = safe_dn(dn)

        if not isinstance(changes, dict):
                self.last_error = 'changes must be a dictionary'
                raise LDAPChangeError(self.last_error)

        if not changes:
            self.last_error = 'no changes in modify request'
            raise LDAPChangeError(self.last_error)

        changelist = dict()
        for attribute_name in changes:
            if self.server and self.server.schema and self.check_names:
                if ';' in attribute_name:  # remove tags for checking
                    attribute_name_to_check = attribute_name.split(';')[0]
                else:
                    attribute_name_to_check = attribute_name

                if self.server.schema.attribute_types and attribute_name_to_check.lower() not in conf_attributes_excluded_from_check and attribute_name_to_check not in self.server.schema.attribute_types:
                    self.last_error = 'invalid attribute type ' + attribute_name_to_check
                    raise LDAPAttributeError(self.last_error)
        change = changes[attribute_name]
        if isinstance(change, SEQUENCE_TYPES) and change[0] in [MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT, 0, 1, 2, 3]:
            if len(change) != 2:
                self.last_error = 'malformed change'
                raise LDAPChangeError(self.last_error)
            changelist[attribute_name] = [change]  # insert change in a list
        else:
            for change_operation in change:
                if len(change_operation) != 2 or change_operation[0] not in [MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT, 0, 1, 2, 3]:
                    self.last_error = 'invalid change list'
                    raise LDAPChangeError(self.last_error)
            changelist[attribute_name] = change
        
        request = modify_operation(self.host, dn, changelist, self.auto_encode, self.server.schema if self.server else None, validator=self.server.custom_validator if self.server else None, check_names=self.check_names)
        response = self.send_and_recv(request)
        et = handle_str_to_xml(response)
        if not et:
            raise ValueError("was unable to parse xml from the server response")

        return True

    def add(self,
            dn,
            object_class=None,
            attributes=None,
            controls=None):
        """
        Add dn to the DIT, object_class is None, a class name or a list
        of class names.

        Attributes is a dictionary in the form 'attr': 'val' or 'attr':
        ['val1', 'val2', ...] for multivalued attributes
        """
        if self.resource != RESOURCE:
            logging.warning("Add is only supported for the \"Resource\" resource, reconnecting to the server")
            self.reconnect(RESOURCE)

        pass

    def delete(self,
               dn,
               controls=None):
        """
        Delete the entry identified by the DN from the DIB.
        """
        if self.resource != RESOURCE:
            logging.warning("Delete is only supported for the \"Resource\" resource, reconnecting to the server")
            self.reconnect(RESOURCE)

        pass

    def connect(self, resource=None, get_info=False):
        """Connect to the specified ADWS endpoint at the
        Args:
            resource (str): endpoint to connect to <'Resource', 'ResourceFactory',
                'Enumeration', AccountManagement',  'TopologyManagement'>
        """
        server_address: tuple[str, int] = (self.host, self.port)
        resource = resource if resource is not None else self.resource
        logging.debug(f"Connecting to {self.host} for {resource}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_address)
        self.nmf = NMFConnection(
            self._create_NNS_from_auth(sock),
            fqdn=self.host,
            port=self.port
        )
        self.nmf.connect(f"Windows/{resource}")
        self.resource = resource
        if get_info:
            self.refresh_server_info()
        return self.server, self

    def reconnect(self, resource=None):
        """
        Reconnect to the server with a new resource
        """
        try:
            logging.debug(f"Reconnecting to {self.host} for {resource}")
            if hasattr(self, 'nmf') and self.nmf is not None:
                try:
                    self.nmf._sock.close()
                except Exception:
                    pass
            return self.connect(resource)
        except Exception as e:
            raise ADWSError(f"Failed to reconnect: {str(e)}")
