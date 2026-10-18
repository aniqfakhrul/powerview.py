"""LDAP SASL framing for application-owned protection contexts.

Keeping framing at the socket boundary avoids ldap3 dispatching a Python
context to a platform-native GSSAPI backend. Bind negotiation finishes before
this adapter is installed; reauthentication must use a fresh transport.
"""
import struct

from powerview.lib.krb5.gss import GSSError


class SaslSocket:
	MAX_FRAME_SIZE = 64 * 1024 * 1024

	def __init__(self, connection, context, buffer_size):
		self._connection = connection
		self._socket = connection.socket
		self._context = context
		self._plain = bytearray()
		self._wrap_limit = context.get_wrap_size_limit(buffer_size - 4)
		if self._wrap_limit <= 0:
			raise GSSError('LDAP SASL buffer is too small for message protection')

	def __getattr__(self, name):
		return getattr(self._socket, name)

	def close(self):
		self._plain.clear()
		self._socket.close()

	def sendall(self, message, flags=0):
		if flags:
			raise ValueError('LDAP SASL transport does not support socket flags')
		try:
			if self._connection.sasl_in_progress:
				raise GSSError('Kerberos reauthentication requires a fresh connection')
			for offset in range(0, len(message), self._wrap_limit):
				token = self._context.wrap(message[offset:offset + self._wrap_limit], True).message
				self._socket.sendall(struct.pack('>I', len(token)) + token)
		except (Exception, KeyboardInterrupt):
			self._connection.strategy.close()
			raise

	def _read_exactly(self, size):
		result = bytearray()
		while len(result) < size:
			chunk = self._socket.recv(size - len(result))
			if not chunk:
				raise ConnectionError('Connection closed before the LDAP SASL frame was complete')
			result.extend(chunk)
		return bytes(result)

	def recv(self, size, flags=0):
		if flags or size < 0:
			raise ValueError('Invalid LDAP SASL socket receive arguments')
		if size == 0:
			return b''
		try:
			while not self._plain:
				length = struct.unpack('>I', self._read_exactly(4))[0]
				if not 0 < length <= self.MAX_FRAME_SIZE:
					raise GSSError(f'Invalid LDAP SASL frame size: {length}')
				self._plain.extend(self._context.unwrap(self._read_exactly(length)).message)
			message = bytes(self._plain[:size])
			del self._plain[:size]
			return message
		except (Exception, KeyboardInterrupt):
			self._connection.strategy.close()
			raise


def install_ldap_protection(connection, context, buffer_size):
	connection.socket = SaslSocket(connection, context, buffer_size)
	connection.krb_ctx = context
	# The adapter owns framing. Disable ldap3's native wrapping to avoid applying
	# protection twice or passing this Python context to winkerberos.
	connection.session_security = None
