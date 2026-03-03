from .. import OPERATIONAL_ATTRIBUTES, RESOURCE, RESOURCE_FACTORY, ENUMERATION, ACCOUNT_MANAGEMENT, TOPOLOGY_MANAGEMENT, COMMON_ATTRIBUTES
from ..operation.search import search_operation, search_pull_operation, search_enumerate_response_to_dict, search_pull_response_to_dict
from ..operation.modify import modify_operation, modify_response_to_dict
from ..operation.delete import delete_operation, delete_response_to_dict
from ..operation.add import add_operation, add_response_to_dict
from ..operation.modifyDN import modify_dn_operation, modify_dn_response_to_dict
from ..operation.customaction import set_password_operation, change_password_operation, password_response_to_dict
from ..nns import NNS
from ..nmf import NMFConnection
from ..error import ADWSError

from ldap3.utils.dn import safe_dn
from ldap3 import (
    ALL_ATTRIBUTES, NO_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, NTLM, BASE, LEVEL, SUBTREE, 
    STRING_TYPES, get_config_parameter, SEQUENCE_TYPES, MODIFY_ADD, MODIFY_DELETE, 
    MODIFY_REPLACE, MODIFY_INCREMENT, SYNC, SAFE_SYNC, SAFE_RESTARTABLE, ASYNC, LDIF, 
    RESTARTABLE, REUSABLE, MOCK_SYNC, MOCK_ASYNC, ASYNC_STREAM
)
from ldap3.core.connection import CLIENT_STRATEGIES
from ldap3.protocol.rfc2696 import paged_search_control
from ldap3.core.exceptions import LDAPChangeError, LDAPAttributeError, LDAPUnknownStrategyError, LDAPObjectClassError
from ldap3.protocol.formatters.standard import format_attribute_values
from ldap3.strategy.sync import SyncStrategy
from ldap3.strategy.safeSync import SafeSyncStrategy
from ldap3.strategy.safeRestartable import SafeRestartableStrategy
from ldap3.strategy.mockAsync import MockAsyncStrategy
from ldap3.strategy.asynchronous import AsyncStrategy
from ldap3.strategy.reusable import ReusableStrategy
from ldap3.strategy.restartable import RestartableStrategy
from ldap3.strategy.ldifProducer import LdifProducerStrategy
from ldap3.strategy.mockSync import MockSyncStrategy
from ldap3.strategy.asyncStream import AsyncStreamStrategy
from ldap3.utils.conv import to_unicode

import logging
import socket
from copy import deepcopy
from functools import reduce

class Connection(object):
    def __init__(self, server, user, password, domain, lmhash, nthash, raise_exceptions=False, authentication=NTLM, check_names=True, auto_encode=True, client_strategy=SYNC):
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
        self.result = {}
        
        # Add ldap3-compatible attributes
        self.bound = False
        self.closed = True
        self.last_error = None
        self.entries = []

        # Add compatibility attributes for connection pooling
        self.nmf = None

        conf_default_pool_name = get_config_parameter('DEFAULT_THREADED_POOL_NAME')
        if client_strategy not in CLIENT_STRATEGIES:
            if self.raise_exceptions:
                raise LDAPUnknownStrategyError('unknown client connection strategy')
            else:
                logging.error('unknown client connection strategy')
                return
        
        self.strategy_type = client_strategy
        if self.strategy_type == SYNC:
            self.strategy = SyncStrategy(self)
        elif self.strategy_type == SAFE_SYNC:
            self.strategy = SafeSyncStrategy(self)
        elif self.strategy_type == SAFE_RESTARTABLE:
            self.strategy = SafeRestartableStrategy(self)
        elif self.strategy_type == ASYNC:
            self.strategy = AsyncStrategy(self)
        elif self.strategy_type == LDIF:
            self.strategy = LdifProducerStrategy(self)
        elif self.strategy_type == RESTARTABLE:
            self.strategy = RestartableStrategy(self)
        elif self.strategy_type == REUSABLE:
            self.strategy = ReusableStrategy(self)
            self.lazy = False
        elif self.strategy_type == MOCK_SYNC:
            self.strategy = MockSyncStrategy(self)
        elif self.strategy_type == MOCK_ASYNC:
            self.strategy = MockAsyncStrategy(self)
        elif self.strategy_type == ASYNC_STREAM:
            self.strategy = AsyncStreamStrategy(self)
        else:
            if self.raise_exceptions:
                raise LDAPUnknownStrategyError('unknown strategy')
            else:
                logging.error('unknown strategy')
                
    def unbind(self):
        """
        Close the connection and mark as unbound.
        Compatible with ldap3.Connection.unbind()
        """
        try:
            if hasattr(self, 'nmf') and self.nmf is not None:
                try:
                    self.nmf._sock.close()
                except Exception:
                    pass
                self.nmf = None
        except Exception:
            pass
        finally:
            self.bound = False
            self.closed = True
    
    def close(self):
        """
        Close the connection. Alias for unbind() for compatibility.
        """
        self.unbind()
    
    def is_connection_alive(self):
        """
        Check if the ADWS connection is alive.
        Uses getpeername() to verify the underlying socket is still connected.
        Does NOT use select/MSG_PEEK which corrupts the NNS encrypted stream.
        """
        try:
            if self.closed or not self.bound:
                return False
            if not hasattr(self, 'nmf') or self.nmf is None:
                return False
            # Use getpeername() to check if socket is still connected
            self.nmf._sock.getpeername()
            return True
        except (OSError, AttributeError):
            return False
    
    def abandon(self, message_id):
        """
        ADWS has no abandon operation. Used for keep-alive compatibility with ldap3.
        """
        return self.is_connection_alive()

    def keep_alive(self):
        """
        Check if the ADWS connection is still alive.
        Compatible with the connection pool interface.
        """
        return self.is_connection_alive()

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

    def _prepare_return_value(self, response):
        error_detail = response.get("ErrorDetail", {})
        fault_detail = error_detail.get("FaultDetail", {})
        specific_error = {}

        if isinstance(fault_detail, dict) and fault_detail:
            specific_error = next(iter(fault_detail.values()), {})
            if not isinstance(specific_error, dict):
                specific_error = {}

        self.result['message'] = specific_error.get("ExtendedErrorMessage", fault_detail.get("ExtendedErrorMessage", response.get("Error", "Unknown error")))
        self.result['description'] = specific_error.get("Message", fault_detail.get("ExtendedErrorDescription", response.get("Error", "Unknown error")))

        error_code_val = specific_error.get("ErrorCode", fault_detail.get("ErrorCode", 0))
        try:
            self.result['result'] = int(error_code_val)
        except (ValueError, TypeError):
            self.result['result'] = str(error_code_val) if error_code_val else 0

        win32_error_code_val = specific_error.get("Win32ErrorCode", 0)
        try:
            self.result['win32_error_code'] = int(win32_error_code_val)
        except (ValueError, TypeError):
            self.result['win32_error_code'] = 0

        self.result['short_message'] = specific_error.get("ShortMessage", fault_detail.get("ShortError", "Unknown"))

        self.entries = response.get("entries", [])
        response['entries'] = self.entries

    def refresh_server_info(self):
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
            request = search_operation(self.host, search_base, search_filter, search_scope, attributes, controls=controls)
            response = self.send_and_recv(request)
            enum_resp = search_enumerate_response_to_dict(response)
            enum_ctx = enum_resp['EnumerationContext']

            # Pull results in a loop until EndOfSequence.
            # In WS-Enumeration the EnumerationContext is a session handle that
            # stays the same across pulls — the server tracks cursor position
            # internally.  We stop when:
            #   1. EndOfSequence element is present, OR
            #   2. A non-empty pull returns fewer items than MaxElements (last page)
            MAX_PULL_ELEMENTS = 256  # must match MaxElements in LDAP_PULL_FSTRING
            MAX_EMPTY_PULLS = 3     # safety: consecutive empty pulls before giving up
            all_entries = []
            pull_count = 0
            consecutive_empty = 0
            while True:
                pull_count += 1
                pull_request = search_pull_operation(self.host, enum_ctx, controls=controls)
                response = self.send_and_recv(pull_request)
                resp_dict = search_pull_response_to_dict(response, attributes)

                entries = resp_dict.get('entries', [])
                logging.debug(f"[ADWS] Pull #{pull_count}: {len(entries)} entries, EndOfSequence={resp_dict.get('EndOfSequence', False)}")

                if entries:
                    consecutive_empty = 0
                    for entry in entries:
                        for attribute in entry['attributes']:
                            entry['attributes'][attribute] = format_attribute_values(self.server.schema, attribute, entry['attributes'][attribute], self.server.custom_formatter)
                    all_entries.extend(entries)
                else:
                    consecutive_empty += 1

                # EndOfSequence in response means we're done
                if resp_dict.get('EndOfSequence'):
                    self.last_cookie = None
                    break

                # A non-empty pull with fewer entries than MaxElements = last page
                if entries and len(entries) < MAX_PULL_ELEMENTS:
                    self.last_cookie = None
                    break

                # Safety: too many consecutive empty pulls means something is wrong
                if consecutive_empty >= MAX_EMPTY_PULLS:
                    logging.debug(f"[ADWS] {MAX_EMPTY_PULLS} consecutive empty pulls, stopping")
                    self.last_cookie = None
                    break

                # Update enum context if server provides a new one
                new_enum_ctx = resp_dict.get('EnumerationContext')
                if new_enum_ctx:
                    enum_ctx = new_enum_ctx

            logging.debug(f"[ADWS] Search complete: {len(all_entries)} total entries in {pull_count} pulls")
            self.entries = all_entries
            return True
        except ADWSError as e:
            if "size limit was exceeded" in str(e).lower() and attributes and isinstance(attributes, list) and attributes != [ALL_ATTRIBUTES]:
                logging.warning("Size limit was exceeded, retrying with wildcard attributes")
                return self.search(search_base, search_filter, search_scope, [ALL_ATTRIBUTES], size_limit, time_limit, types_only, get_operational_attributes, controls, paged_size, paged_criticality, paged_cookie, auto_escape)
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
        
        request = modify_operation(self.host, dn, changelist, self.auto_encode, self.server.schema if self.server else None, validator=self.server.custom_validator if self.server else None, check_names=self.check_names, controls=controls)
        response = self.send_and_recv(request)
        resp_dict = modify_response_to_dict(response)
        self._prepare_return_value(resp_dict)
        if resp_dict.get("Error"):
            if self.raise_exceptions:
                raise ADWSError(f"{self.result['short_message']}: {self.result['description']}")
            else:
                logging.error(f"{self.result['short_message']}: {self.result['description']}")
                return False
        else:
            return True

    def modify_dn(self,
                  dn,
                  relative_dn,
                  delete_old_dn=True,
                  new_superior=None,
                  controls=None):
        """
        Modify DN of the entry or performs a move of the entry in the
        DIT.
        """

        if self.resource != RESOURCE:
            logging.debug("ModifyDN is only supported for the \"Resource\" resource, reconnecting to the server")
            self.reconnect(RESOURCE)

        request = modify_dn_operation(self.host, dn, relative_dn, delete_old_dn, new_superior, controls=controls)
        response = self.send_and_recv(request)
        resp_dict = modify_dn_response_to_dict(response)
        self._prepare_return_value(resp_dict)
        if resp_dict.get("Error"):
            if self.raise_exceptions:
                raise ADWSError(f"{self.result['short_message']}: {self.result['description']}")
            else:
                logging.error(f"{self.result['short_message']}: {self.result['description']}")
                return False
        else:
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
        if self.resource != RESOURCE_FACTORY:
            logging.debug("Add is only supported for the \"ResourceFactory\" resource, reconnecting to the server")
            self.reconnect(RESOURCE_FACTORY)

        conf_attributes_excluded_from_check = [v.lower() for v in get_config_parameter('ATTRIBUTES_EXCLUDED_FROM_CHECK')]
        conf_classes_excluded_from_check = [v.lower() for v in get_config_parameter('CLASSES_EXCLUDED_FROM_CHECK')]

        self.last_error = None
        _attributes = deepcopy(attributes)
        if self.check_names:
            dn = safe_dn(dn)

        attr_object_class = []
        if object_class is None:
            parm_object_class = []
        else:
            parm_object_class = list(object_class) if isinstance(object_class, SEQUENCE_TYPES) else [object_class]

        object_class_attr_name = ''
        if _attributes:
            for attr in _attributes:
                if attr.lower() == 'objectclass':
                    object_class_attr_name = attr
                    attr_object_class = list(_attributes[object_class_attr_name]) if isinstance(_attributes[object_class_attr_name], SEQUENCE_TYPES) else [_attributes[object_class_attr_name]]
                    break
        else:
            _attributes = dict()

        if not object_class_attr_name:
                object_class_attr_name = 'objectClass'

        attr_object_class = [to_unicode(object_class) for object_class in attr_object_class]  # converts objectclass to unicode in case of bytes value
        _attributes[object_class_attr_name] = reduce(lambda x, y: x + [y] if y not in x else x, parm_object_class + attr_object_class, [])  # remove duplicate ObjectClasses

        if not _attributes[object_class_attr_name]:
            raise LDAPObjectClassError('objectClass attribute is mandatory')

        if self.server and self.server.schema and self.check_names:
            for object_class_name in _attributes[object_class_attr_name]:
                if object_class_name.lower() not in conf_classes_excluded_from_check and object_class_name not in self.server.schema.object_classes:
                    raise LDAPObjectClassError('invalid object class ' + str(object_class_name))

            for attribute_name in _attributes:
                if ';' in attribute_name:  # remove tags for checking
                    attribute_name_to_check = attribute_name.split(';')[0]
                else:
                    attribute_name_to_check = attribute_name

                if attribute_name_to_check.lower() not in conf_attributes_excluded_from_check and attribute_name_to_check not in self.server.schema.attribute_types:
                    raise LDAPAttributeError('invalid attribute type ' + attribute_name_to_check)

        request = add_operation(self.host, dn, _attributes, controls=controls)
        response = self.send_and_recv(request)
        resp_dict = add_response_to_dict(response)
        self._prepare_return_value(resp_dict)
        if resp_dict.get("Error"):
            if self.raise_exceptions:
                raise ADWSError(f"{self.result['short_message']}: {self.result['description']}")
            else:
                logging.error(f"{self.result['short_message']}: {self.result['description']}")
                return False
        else:
            return True

    def delete(self,
               dn,
               controls=None):
        """
        Delete the entry identified by the DN from the DIB.
        """
        if self.resource != RESOURCE:
            logging.debug("Delete is only supported for the \"Resource\" resource, reconnecting to the server")
            self.reconnect(RESOURCE)

        request = delete_operation(self.host, dn, controls=controls)
        response = self.send_and_recv(request)
        resp_dict = delete_response_to_dict(response)
        self._prepare_return_value(resp_dict)
        if resp_dict.get("Error"):
            if self.raise_exceptions:
                raise ADWSError(self.result['message'])
            else:
                logging.error(self.result['message'])
                return False
        else:
            return True

    @staticmethod
    def _derive_partition_dn(account_dn):
        """Extract partition DN (DC= components) from an account DN."""
        parts = [p.strip() for p in account_dn.split(',')]
        dc_parts = [p for p in parts if p.upper().startswith('DC=')]
        return ','.join(dc_parts) if dc_parts else ''

    def set_password(self, account_dn, new_password, partition_dn=None):
        """Reset an account's password via ADWS AccountManagement (SetPassword).

        This is an admin password reset — no old password required.
        Requires Reset Password permission on the target object.

        Args:
            account_dn:   DN of the target account
            new_password: New password to set
            partition_dn: Domain partition DN (auto-derived if None)

        Returns:
            True on success

        Raises:
            ADWSError: On SOAP fault
        """
        if self.resource != ACCOUNT_MANAGEMENT:
            logging.debug("SetPassword requires AccountManagement endpoint, reconnecting")
            self.reconnect(ACCOUNT_MANAGEMENT)

        if not partition_dn:
            partition_dn = self._derive_partition_dn(account_dn)

        request = set_password_operation(self.host, account_dn, new_password, partition_dn)
        response = self.send_and_recv(request)
        resp_dict = password_response_to_dict(response)
        self._prepare_return_value(resp_dict)
        if resp_dict.get("Error"):
            if self.raise_exceptions:
                raise ADWSError(resp_dict)
            else:
                logging.error(f"SetPassword failed: {self.result['description']}")
                return False
        return True

    def change_password(self, account_dn, old_password, new_password, partition_dn=None):
        """Change an account's password via ADWS AccountManagement (ChangePassword).

        Requires knowledge of the current password. Any authenticated user
        can change their own password this way.

        Args:
            account_dn:   DN of the target account
            old_password: Current password
            new_password: New password to set
            partition_dn: Domain partition DN (auto-derived if None)

        Returns:
            True on success, False on error (if raise_exceptions=False)

        Raises:
            ADWSError: On SOAP fault (if raise_exceptions=True)
        """
        if self.resource != ACCOUNT_MANAGEMENT:
            logging.debug("ChangePassword requires AccountManagement endpoint, reconnecting")
            self.reconnect(ACCOUNT_MANAGEMENT)

        if not partition_dn:
            partition_dn = self._derive_partition_dn(account_dn)

        request = change_password_operation(self.host, account_dn, old_password, new_password, partition_dn)
        response = self.send_and_recv(request)
        resp_dict = password_response_to_dict(response)
        self._prepare_return_value(resp_dict)
        if resp_dict.get("Error"):
            if self.raise_exceptions:
                raise ADWSError(resp_dict)
            else:
                logging.error(f"ChangePassword failed: {self.result['description']}")
                return False
        return True

    def connect(self, resource=None, get_info=False):
        """Connect to the specified ADWS endpoint at the
        Args:
            resource (str): endpoint to connect to <'Resource', 'ResourceFactory',
                'Enumeration', AccountManagement',  'TopologyManagement'>
        """
        try:
            server_address: tuple[str, int] = (self.host, self.port)
            resource = resource if resource is not None else self.resource
            logging.debug(f"[ADWS] Connecting to {self.host}:{self.port} for {resource}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(server_address)
            logging.debug(f"[ADWS] TCP connection established, starting NNS/NTLM authentication")
            self.nmf = NMFConnection(
                self._create_NNS_from_auth(sock),
                fqdn=self.host,
                port=self.port
            )
            self.nmf.connect(f"Windows/{resource}")
            logging.debug(f"[ADWS] NMF session established for {resource}")
            self.resource = resource

            # Set connection state
            self.bound = True
            self.closed = False
        except Exception as e:
            self.bound = False
            self.closed = True
            raise ADWSError(f"Failed to connect: {str(e)}")

        if get_info:
            logging.debug(f"[ADWS] Fetching server info (DSA + schema)")
            try:
                self.refresh_server_info()
                logging.debug(f"[ADWS] Server info loaded successfully")
            except Exception as e:
                logging.warning(f"[ADWS] Failed to load server info: {str(e)}. Connection is still usable.")
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
            self.bound = False
            self.closed = True
            raise ADWSError(f"Failed to reconnect: {str(e)}")
