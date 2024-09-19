#!/usr/bin/env python3
import logging
import socket
import re
import requests
from requests_ntlm import HttpNtlmAuth

class SCCM():
	def __init__(self, target):
		self.target = target
		self.http_enabled = False
		self.http_anonymous_enabled = False

	def http_enabled(self):
		return self.http_enabled

	def http_anonymous_enabled(self):
		return self.http_anonymous_enabled

	def check_datalib_endpoint(self, port=80):
	    try:
	        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        logging.debug("Default timeout is set to 5")
	        sock.settimeout(timeout)
	        logging.debug("Connecting to %s:%d" % (self.target, port))
	        sock.connect((self.target, port))
	        sock.sendall(
	            "\r\n".join(
	                ["HEAD /SMS_DP_SMSPKG$/Datalib HTTP/1.1", "Host: %s" % self.target, "\r\n"]
	            ).encode()
	        )
	        resp = sock.recv(256)
	        sock.close()
	        head = resp.split(b"\r\n")[0].decode()

	        self.http_enabled = True
	        if "200" in head.strip():
	        	self.http_anonymous_enabled = True
	    except ConnectionRefusedError:
	        self.http_enabled = False
	    except socket.timeout:
	        logging.debug("Can't reach %s" % (self.target))
	        self.http_enabled = False
	    except Exception as e:
	        logging.warning(
	            "Got error while trying to check for web enrollment: %s" % e
	        )
	        self.http_enabled = False

	def parse_datalib(usernama, password):
		urls = []
		url = "http://%s/SMS_DP_SMSPKG$/Datalib"
		headers = {
			"User-Agent": "Mozilla"
		}
		request_kwargs = {
			"url": url,
			"headers":  headers,
			"auth": HttpNtlmAuth(username, password)
		}

		res = requests.get(**request_kwargs)
		print(res.content)
		return urls
