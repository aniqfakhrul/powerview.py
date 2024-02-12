#!/usr/bin/env python3
try:
    from ldap3 import (
        Connection,
        ENCRYPT,
        SIMPLE,
        ANONYMOUS,
        SASL,
        NTLM
    )
except ImportError as e:
    pass

from ldap3.utils.log import log_enabled, BASIC

class Connection(Connection):
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
            if self.session_security == ENCRYPT or self._digest_md5_kcs_cipher:
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
