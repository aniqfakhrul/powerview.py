#!/usr/bin/env python3
import logging
import socket

class SCCM():
	def __init__(self, target):
		self.target = target
		self._http_enabled = False
		self._http_anonymous_enabled = False

	def http_enabled(self):
		return self._http_enabled

	def http_anonymous_enabled(self):
		return self._http_anonymous_enabled

	def check_datalib_endpoint(self, port=80, timeout=5):
		self._http_enabled = False
		self._http_anonymous_enabled = False
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
				sock.settimeout(timeout)
				logging.debug("Connecting to %s:%d", self.target, port)
				sock.connect((self.target, port))
				sock.sendall(
					f"HEAD /SMS_DP_SMSPKG$/Datalib HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n".encode()
				)
				head = sock.recv(256).split(b'\r\n', 1)[0].split()
				self._http_enabled = len(head) >= 2 and head[0].startswith(b'HTTP/')
				self._http_anonymous_enabled = self._http_enabled and head[1] == b'200'
		except OSError as error:
			logging.debug("Can't reach SCCM Datalib endpoint %s: %s", self.target, error)
