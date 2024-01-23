import ssl
from ldap3.core.tls import Tls

class Tls(Tls):
    def __init__(self,
                 local_private_key_file=None,
                 local_certificate_file=None,
                 validate=ssl.CERT_NONE,
                 version=None,
                 ssl_options=None,
                 ca_certs_file=None,
                 valid_names=None,
                 ca_certs_path=None,
                 ca_certs_data=None,
                 local_private_key_password=None,
                 ciphers=None,
                 sni=None,
                 peer_certificate=None):
        if ssl_options is None:
            ssl_options = []
        self.ssl_options = ssl_options
        if validate in [ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED]:
            self.validate = validate
        elif validate:
            if log_enabled(ERROR):
                log(ERROR, 'invalid validate parameter <%s>', validate)
            raise LDAPSSLConfigurationError('invalid validate parameter')
        if ca_certs_file and path.exists(ca_certs_file):
            self.ca_certs_file = ca_certs_file
        elif ca_certs_file:
            if log_enabled(ERROR):
                log(ERROR, 'invalid CA public key file <%s>', ca_certs_file)
            raise LDAPSSLConfigurationError('invalid CA public key file')
        else:
            self.ca_certs_file = None

        if ca_certs_path and use_ssl_context and path.exists(ca_certs_path):
            self.ca_certs_path = ca_certs_path
        elif ca_certs_path and not use_ssl_context:
            if log_enabled(ERROR):
                log(ERROR, 'cannot use CA public keys path, SSLContext not available')
            raise LDAPSSLNotSupportedError('cannot use CA public keys path, SSLContext not available')
        elif ca_certs_path:
            if log_enabled(ERROR):
                log(ERROR, 'invalid CA public keys path <%s>', ca_certs_path)
            raise LDAPSSLConfigurationError('invalid CA public keys path')
        else:
            self.ca_certs_path = None

        if ca_certs_data and use_ssl_context:
            self.ca_certs_data = ca_certs_data
        elif ca_certs_data:
            if log_enabled(ERROR):
                log(ERROR, 'cannot use CA data, SSLContext not available')
            raise LDAPSSLNotSupportedError('cannot use CA data, SSLContext not available')
        else:
            self.ca_certs_data = None

        if local_private_key_password and use_ssl_context:
            self.private_key_password = local_private_key_password
        elif local_private_key_password:
            if log_enabled(ERROR):
                log(ERROR, 'cannot use local private key password, SSLContext not available')
            raise LDAPSSLNotSupportedError('cannot use local private key password, SSLContext is not available')
        else:
            self.private_key_password = None

        self.version = version
        self.private_key_file = local_private_key_file
        self.certificate_file = local_certificate_file
        self.valid_names = valid_names
        self.ciphers = ciphers
        self.sni = sni

        if log_enabled(BASIC):
            log(BASIC, 'instantiated Tls: <%r>' % self)

    def wrap_socket(self, connection, do_handshake=False):
        """
        Adds TLS to the connection socket
        """
        if use_ssl_context:
            if self.version is None:  # uses the default ssl context for reasonable security
                ssl_context = create_default_context(purpose=Purpose.SERVER_AUTH,
                                                     cafile=self.ca_certs_file,
                                                     capath=self.ca_certs_path,
                                                     cadata=self.ca_certs_data)
            else:  # code from create_default_context in the Python standard library 3.5.1, creates a ssl context with the specificd protocol version
                ssl_context = ssl.SSLContext(self.version)
                if self.ca_certs_file or self.ca_certs_path or self.ca_certs_data:
                    ssl_context.load_verify_locations(self.ca_certs_file, self.ca_certs_path, self.ca_certs_data)
                elif self.validate != ssl.CERT_NONE:
                    ssl_context.load_default_certs(Purpose.SERVER_AUTH)

            if self.certificate_file:
                ssl_context.load_cert_chain(self.certificate_file, keyfile=self.private_key_file, password=self.private_key_password)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = self.validate
            for option in self.ssl_options:
                ssl_context.options |= option

            if self.ciphers:
                try:
                    ssl_context.set_ciphers(self.ciphers)
                except ssl.SSLError:
                    pass

            if self.sni:
                wrapped_socket = ssl_context.wrap_socket(connection.socket, server_side=False, do_handshake_on_connect=do_handshake, server_hostname=self.sni)
            else:
                wrapped_socket = ssl_context.wrap_socket(connection.socket, server_side=False, do_handshake_on_connect=do_handshake)
            if log_enabled(NETWORK):
                log(NETWORK, 'socket wrapped with SSL using SSLContext for <%s>', connection)
        else:
            if self.version is None and hasattr(ssl, 'PROTOCOL_SSLv23'):
                self.version = ssl.PROTOCOL_SSLv23
            if self.ciphers:
                try:

                    wrapped_socket = ssl.wrap_socket(connection.socket,
                                                     keyfile=self.private_key_file,
                                                     certfile=self.certificate_file,
                                                     server_side=False,
                                                     cert_reqs=self.validate,
                                                     ssl_version=self.version,
                                                     ca_certs=self.ca_certs_file,
                                                     do_handshake_on_connect=do_handshake,
                                                     ciphers=self.ciphers)
                except ssl.SSLError:
                    raise
                except TypeError:  # in python2.6 no ciphers argument is present, failback to self.ciphers=None
                    self.ciphers = None

            if not self.ciphers:
                wrapped_socket = ssl.wrap_socket(connection.socket,
                                                 keyfile=self.private_key_file,
                                                 certfile=self.certificate_file,
                                                 server_side=False,
                                                 cert_reqs=self.validate,
                                                 ssl_version=self.version,
                                                 ca_certs=self.ca_certs_file,
                                                 do_handshake_on_connect=do_handshake)
            if log_enabled(NETWORK):
                log(NETWORK, 'socket wrapped with SSL for <%s>', connection)

        if do_handshake and (self.validate == ssl.CERT_REQUIRED or self.validate == ssl.CERT_OPTIONAL):
            check_hostname(wrapped_socket, connection.server.host, self.valid_names)

        self.peer_certificate = wrapped_socket.getpeercert(binary_form=True)
        connection.socket = wrapped_socket
        return
