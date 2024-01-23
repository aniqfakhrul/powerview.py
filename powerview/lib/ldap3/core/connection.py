from threading import RLock
from powerview.lib.ldap3 import ANONYMOUS, SIMPLE, SASL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, get_config_parameter, DEREF_ALWAYS, \
    SUBTREE, ASYNC, SYNC, NO_ATTRIBUTES, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, MODIFY_INCREMENT, LDIF, ASYNC_STREAM, \
    RESTARTABLE, ROUND_ROBIN, REUSABLE, AUTO_BIND_DEFAULT, AUTO_BIND_NONE, AUTO_BIND_TLS_BEFORE_BIND, SAFE_SYNC, SAFE_RESTARTABLE, \
    AUTO_BIND_TLS_AFTER_BIND, AUTO_BIND_NO_TLS, STRING_TYPES, SEQUENCE_TYPES, MOCK_SYNC, MOCK_ASYNC, NTLM, EXTERNAL,\
    DIGEST_MD5, GSSAPI, PLAIN, DSA, SCHEMA, ALL, TLS_CHANNEL_BINDING
from ldap3.core.connection import Connection
from ldap3.core.pooling import ServerPool
from ldap3.extend import ExtendedOperationsRoot
from ldap3.utils.port_validators import check_port_and_port_list
from ldap3.utils.log import log_enabled, BASIC
from ldap3.strategy.sync import SyncStrategy

CLIENT_STRATEGIES = [SYNC,
                     SAFE_SYNC,
                     SAFE_RESTARTABLE,
                     ASYNC,
                     LDIF,
                     RESTARTABLE,
                     REUSABLE,
                     MOCK_SYNC,
                     MOCK_ASYNC,
                     ASYNC_STREAM]

class Connection(Connection):
    def __init__(self,
                 server,
                 user=None,
                 password=None,
                 session_security=None,
                 auto_bind=AUTO_BIND_DEFAULT,
                 version=3,
                 authentication=None,
                 client_strategy=SYNC,
                 auto_referrals=True,
                 auto_range=True,
                 sasl_mechanism=None,
                 sasl_credentials=None,
                 check_names=True,
                 collect_usage=False,
                 channel_binding=None,
                 read_only=False,
                 lazy=False,
                 raise_exceptions=False,
                 pool_name=None,
                 pool_size=None,
                 pool_lifetime=None,
                 cred_store=None,
                 fast_decoder=True,
                 receive_timeout=None,
                 return_empty_attributes=True,
                 use_referral_cache=False,
                 auto_escape=True,
                 auto_encode=True,
                 pool_keepalive=None,
                 source_address=None,
                 source_port=None,
                 source_port_list=None):

        conf_default_pool_name = get_config_parameter('DEFAULT_THREADED_POOL_NAME')
        self.connection_lock = RLock()  # re-entrant lock to ensure that operations in the Connection object are executed atomically in the same thread
        with self.connection_lock:
            if client_strategy not in CLIENT_STRATEGIES:
                self.last_error = 'unknown client connection strategy'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPUnknownStrategyError(self.last_error)

            self.strategy_type = client_strategy
            self.user = user
            self.password = password

            if not authentication and self.user:
                self.authentication = SIMPLE
            elif not authentication:
                self.authentication = ANONYMOUS
            elif authentication in [SIMPLE, ANONYMOUS, SASL, NTLM]:
                self.authentication = authentication
            else:
                self.last_error = 'unknown authentication method'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPUnknownAuthenticationMethodError(self.last_error)

            self.version = version
            self.auto_referrals = True if auto_referrals else False
            self.request = None
            self.response = None
            self.result = None
            self.bound = False
            self.listening = False
            self.closed = True
            self.last_error = None
            if auto_bind is False:  # compatibility with older version where auto_bind was a boolean
                self.auto_bind = AUTO_BIND_DEFAULT
            elif auto_bind is True:
                self.auto_bind = AUTO_BIND_NO_TLS
            else:
                self.auto_bind = auto_bind
            self.sasl_mechanism = sasl_mechanism
            self.sasl_credentials = sasl_credentials
            self._usage = ConnectionUsage() if collect_usage else None
            self.socket = None
            self.tls_started = False
            self.sasl_in_progress = False
            self.read_only = read_only
            self._context_state = []
            self._deferred_open = False
            self._deferred_bind = False
            self._deferred_start_tls = False
            self._bind_controls = None
            self._executing_deferred = False
            self.lazy = lazy
            self.pool_name = pool_name if pool_name else conf_default_pool_name
            self.pool_size = pool_size
            self.cred_store = cred_store
            self.pool_lifetime = pool_lifetime
            self.pool_keepalive = pool_keepalive
            self.starting_tls = False
            self.check_names = check_names
            self.raise_exceptions = raise_exceptions
            self.auto_range = True if auto_range else False
            self.extend = ExtendedOperationsRoot(self)
            self._entries = []
            self.fast_decoder = fast_decoder
            self.receive_timeout = receive_timeout
            self.empty_attributes = return_empty_attributes
            self.use_referral_cache = use_referral_cache
            self.auto_escape = auto_escape
            self.auto_encode = auto_encode
            self._digest_md5_kic = None
            self._digest_md5_kis = None
            self._digest_md5_sec_num = 0
            self.krb_ctx = None

            if session_security and not (self.authentication == NTLM or self.sasl_mechanism == GSSAPI):
                self.last_error = '"session_security" option only available for NTLM and GSSAPI'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPInvalidValueError(self.last_error)
            self.session_security = session_security

            port_err = check_port_and_port_list(source_port, source_port_list)
            if port_err:
                if log_enabled(ERROR):
                    log(ERROR, port_err)
                raise LDAPInvalidPortError(port_err)
            # using an empty string to bind a socket means "use the default as if this wasn't provided" because socket
            # binding requires that you pass something for the ip if you want to pass a specific port
            self.source_address = source_address if source_address is not None else ''
            # using 0 as the source port to bind a socket means "use the default behavior of picking a random port from
            # all ports as if this wasn't provided" because socket binding requires that you pass something for the port
            # if you want to pass a specific ip
            self.source_port_list = [0]
            if source_port is not None:
                self.source_port_list = [source_port]
            elif source_port_list is not None:
                self.source_port_list = source_port_list[:]

            if isinstance(server, STRING_TYPES):
                server = Server(server)
            if isinstance(server, SEQUENCE_TYPES):
                server = ServerPool(server, ROUND_ROBIN, active=True, exhaust=True)

            if isinstance(server, ServerPool):
                self.server_pool = server
                self.server_pool.initialize(self)
                self.server = self.server_pool.get_current_server(self)
            else:
                self.server_pool = None
                self.server = server

            if channel_binding == TLS_CHANNEL_BINDING and not (self.authentication == NTLM and self.server.ssl):
                self.last_error = '"channel_binding" option only available for NTLM authentication over LDAPS'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPInvalidValueError(self.last_error)
            self.channel_binding = channel_binding

            # if self.authentication == SIMPLE and self.user and self.check_names:
            #     self.user = safe_dn(self.user)
            #     if log_enabled(EXTENDED):
            #         log(EXTENDED, 'user name sanitized to <%s> for simple authentication via <%s>', self.user, self)

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
                self.last_error = 'unknown strategy'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPUnknownStrategyError(self.last_error)

            # maps strategy functions to connection functions
            self.send = self.strategy.send
            self.open = self.strategy.open
            self.get_response = self.strategy.get_response
            self.post_send_single_response = self.strategy.post_send_single_response
            self.post_send_search = self.strategy.post_send_search

            if not self.strategy.no_real_dsa:
                self._do_auto_bind()
            # else:  # for strategies with a fake server set get_info to NONE if server hasn't a schema
            #     if self.server and not self.server.schema:
            #         self.server.get_info = NONE
            if log_enabled(BASIC):
                if get_library_log_hide_sensitive_data():
                    log(BASIC, 'instantiated Connection: <%s>', self.repr_with_sensitive_data_stripped())
                else:
                    log(BASIC, 'instantiated Connection: <%r>', self)

    def rebind(self,
               user=None,
               password=None,
               authentication=None,
               sasl_mechanism=None,
               sasl_credentials=None,
               read_server_info=True,
               controls=None
               ):

        if log_enabled(BASIC):
            log(BASIC, 'start (RE)BIND operation via <%s>', self)
        self.last_error = None
        with self.connection_lock:
            if self.session_security == ENCRYPT or self.self.connection._digest_md5_kcs_cipher:
                self.last_error = 'Rebind not supported with previous encryption'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPBindError(self.last_error)
            if user:
                self.user = user
            if password is not None:
                self.password = password
            if not authentication and user:
                self.authentication = SIMPLE
            if authentication in [SIMPLE, ANONYMOUS, SASL, NTLM]:
                self.authentication = authentication
            elif authentication is not None:
                self.last_error = 'unknown authentication method'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPUnknownAuthenticationMethodError(self.last_error)
            if sasl_mechanism:
                self.sasl_mechanism = sasl_mechanism
            if sasl_credentials:
                self.sasl_credentials = sasl_credentials

            # if self.authentication == SIMPLE and self.user and self.check_names:
            #     self.user = safe_dn(self.user)
            #     if log_enabled(EXTENDED):
            #         log(EXTENDED, 'user name sanitized to <%s> for rebind via <%s>', self.user, self)

            if not self.strategy.pooled:
                try:
                    return self.bind(read_server_info, controls)
                except LDAPSocketReceiveError:
                    self.last_error = 'Unable to rebind as a different user, furthermore the server abruptly closed the connection'
                    if log_enabled(ERROR):
                        log(ERROR, '%s for <%s>', self.last_error, self)
                    raise LDAPBindError(self.last_error)
            else:
                self.strategy.pool.rebind_pool()
                return self._prepare_return_value(True, self.result)
