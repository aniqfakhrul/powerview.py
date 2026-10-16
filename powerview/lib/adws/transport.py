from ldap3.core.exceptions import LDAPCommunicationError, LDAPSignatureVerificationFailedError


TRANSPORT_ERRORS = (ConnectionError, TimeoutError, LDAPCommunicationError, LDAPSignatureVerificationFailedError)


def receive_exactly(transport, size):
    data = bytearray()
    while len(data) < size:
        chunk = transport.recv(size - len(data))
        if not chunk:
            raise ConnectionError('Connection closed before the response was complete')
        data.extend(chunk)
    return bytes(data)
