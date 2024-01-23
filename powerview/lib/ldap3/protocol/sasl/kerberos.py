from ldap3.core.exceptions import LDAPPackageUnavailableError, LDAPCommunicationError
posix_gssapi_unavailable = True
try:
    # noinspection PyPackageRequirements,PyUnresolvedReferences
    import gssapi
    from gssapi.raw import ChannelBindings
    posix_gssapi_unavailable = False
except ImportError:
    pass

windows_gssapi_unavailable = True
# only attempt to import winkerberos if gssapi is unavailable
if posix_gssapi_unavailable:
    try:
        import winkerberos
        windows_gssapi_unavailable = False
    except ImportError:
        raise LDAPPackageUnavailableError('package gssapi (or winkerberos) missing')

def _common_process_end_token_get_security_layers(negotiated_token, session_security=None):
    """ Process the response we got at the end of our SASL negotiation wherein the server told us what
    minimum security layers we need, and return a bytearray for the client security layers we want.
    This function throws an error on a malformed token from the server.
    The ldap3 library does not support security layers, and only supports authentication with kerberos,
    so an error will be thrown for any tokens that indicate a security layer requirement.
    """
    if len(negotiated_token) != 4:
        raise LDAPCommunicationError("Incorrect response from server")

    server_security_layers = negotiated_token[0]
    if not isinstance(server_security_layers, int):
        server_security_layers = ord(server_security_layers)
    if server_security_layers in (0, NO_SECURITY_LAYER):
        if negotiated_token[1:] != '\x00\x00\x00':
            raise LDAPCommunicationError("Server max buffer size must be 0 if no security layer")
    security_layer = CONFIDENTIALITY_PROTECTION if session_security else NO_SECURITY_LAYER 
    if not (server_security_layers & security_layer):
        raise LDAPCommunicationError("Server doesn't support the security level asked")

    # this is here to encourage anyone implementing client security layers to do it
    # for both windows and posix
    client_security_layers = bytearray([security_layer, 0, 0, 0])
    return client_security_layers

def _windows_sasl_gssapi(connection, controls):
    """ Performs a bind using the Kerberos v5 ("GSSAPI") SASL mechanism
    from RFC 4752 using the winkerberos package that works natively on most
    windows operating systems.
    """
    target_name = _common_determine_target_name(connection)
    # initiation happens before beginning the SASL bind when using windows kerberos
    authz_id, _ = _common_determine_authz_id_and_creds(connection)
    gssflags = (
            winkerberos.GSS_C_MUTUAL_FLAG |
            winkerberos.GSS_C_SEQUENCE_FLAG |
            winkerberos.GSS_C_INTEG_FLAG |
            winkerberos.GSS_C_CONF_FLAG
    )
    _, ctx = winkerberos.authGSSClientInit(target_name, gssflags=gssflags)

    in_token = b''
    try:
        negotiation_complete = False
        while not negotiation_complete:
            # GSSAPI is a "client goes first" SASL mechanism. Send the first "response" to the server and
            # recieve its first challenge.
            # Despite this, we can get channel binding, which includes CBTs for windows environments computed from
            # the peer certificate, before starting.
            status = winkerberos.authGSSClientStep(ctx, base64.b64encode(in_token).decode('utf-8'),
                                                   channel_bindings=get_channel_bindings(connection.socket))
            # figure out if we're done with our sasl negotiation
            negotiation_complete = (status == winkerberos.AUTH_GSS_COMPLETE)
            out_token = winkerberos.authGSSClientResponse(ctx) or ''
            out_token_bytes = base64.b64decode(out_token)
            result = send_sasl_negotiation(connection, controls, out_token_bytes)
            in_token = result['saslCreds'] or b''

        winkerberos.authGSSClientUnwrap(ctx,base64.b64encode(in_token).decode('utf-8'))
        negotiated_token = ''
        if winkerberos.authGSSClientResponse(ctx):
            negotiated_token = base64.standard_b64decode(winkerberos.authGSSClientResponse(ctx))
        client_security_layers = _common_process_end_token_get_security_layers(negotiated_token, connection.session_security)
        # manually construct a message indicating use of authorization-only layer
        # see winkerberos example: https://github.com/mongodb/winkerberos/blob/master/test/test_winkerberos.py
        authz_only_msg = base64.b64encode(bytes(client_security_layers) + authz_id).decode('utf-8')
        winkerberos.authGSSClientWrap(ctx, authz_only_msg)
        out_token = winkerberos.authGSSClientResponse(ctx) or ''
        connection.krb_ctx = ctx
        return send_sasl_negotiation(connection, controls, base64.b64decode(out_token))
    except (winkerberos.GSSError, LDAPCommunicationError):
        abort_sasl_negotiation(connection, controls)
        raise
