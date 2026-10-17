import argparse
import json
import os
import re
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

QUERIES = [
	("user-identity", "Get-DomainUser -Identity Administrator -Properties sAMAccountName"),
	("user-spn", "Get-DomainUser -SPN -Properties sAMAccountName"),
	("computers", "Get-DomainComputer -Properties dNSHostName"),
	("sid-lookup", "Get-DomainObject -Identity {domain_sid}-512 -Properties sAMAccountName"),
	("group-members", "Get-DomainGroupMember -Identity \"Domain Admins\""),
	("dcs", "Get-DomainController -Properties dNSHostName"),
	("uac-bitwise", "Get-DomainUser -LDAPFilter \"(userAccountControl:1.2.840.113556.1.4.803:=65536)\" -Properties sAMAccountName"),
	("whencreated", "Get-DomainUser -LDAPFilter \"(whenCreated>=20200101000000.0Z)\" -Properties sAMAccountName"),
	("memberof-dn", "Get-DomainUser -LDAPFilter \"(memberOf=CN=Domain Admins,CN=Users,{base})\" -Properties sAMAccountName"),
]

BLOCK = re.compile(
	r"Intercepted Search\n    BaseDN: '(?P<ib>.*)'\n    Filter: (?P<if>.*)\n    Attributes: (?P<ia>.*)\n"
	r"(?:.*\[\+\] Applying middleware.*\n)*"
	r"(?:Changed Search\n    BaseDN: '(?P<cb>.*)'\n    Filter: (?P<cf>.*)\n    Attributes: (?P<ca>.*)|Nothing changed in the request)"
)


def start_proxy(binary, dc, port, password, log_path, chains):
	command = [binary, "-t", f"{dc}:389", "-l", f"127.0.0.1:{port}", "-N", "-Z", "-F", "1", "--decrypt-password", password]
	for flag, chain in chains:
		if chain:
			command += [flag, chain]
	handle = open(log_path, "w")
	process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
	time.sleep(1.0)
	return process


def run_powerview(target, query, extra):
	command = ["uv", "run", "powerview.py", target, *extra, "--no-admin-check", "--no-cache", "--no-vuln-check", "--json", "-q", query]
	result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
	output = result.stdout.strip()
	try:
		entries = json.loads(output[output.index("["):]) if "[" in output else []
		return sorted(json.dumps(entry.get("dn", entry), sort_keys=True).lower() for entry in entries), None
	except ValueError:
		lines = (result.stdout + result.stderr).strip().splitlines()
		return None, lines[-1][:200] if lines else "no output"


def wire_searches(log_path, offset):
	with open(log_path, errors="replace") as handle:
		handle.seek(offset)
		text = handle.read()
	searches = []
	for match in BLOCK.finditer(text):
		searches.append((match["cb"] or match["ib"], match["cf"] or match["if"], match["ca"] or match["ia"]))
	return searches


def wire_metrics(searches):
	filters = [f for _, f, _ in searches]
	leaves = lambda f: max(1, len(re.findall(r"\(([^()!&|]+)\)", f)))
	return {
		"searches": len(searches),
		"(!(! per leaf": statistics.mean(f.count("(!(!") / leaves(f) for f in filters) if filters else 0,
		"zero-padded numbers": sum(len(re.findall(r"(?<=[=\-])0+(?=[1-9])", f)) for f in filters),
		"aNR leaves": sum(f.count("(aNR=") for f in filters),
		"basedn hex escapes": statistics.mean(len(re.findall(r"\\[0-9a-fA-F]{2}", b)) for b, _, _ in searches) if searches else 0,
		"OID attributes": sum(len(re.findall(r"\((?i:oid)\.", f)) for f in filters),
	}


def main():
	parser = argparse.ArgumentParser(description="Live A/B: powerview's ldapx port vs upstream ldapx proxy against a real DC")
	parser.add_argument("--dc", required=True)
	parser.add_argument("--identity", required=True, help="domain/user:password")
	parser.add_argument("--password", required=True, help="account password, used by the proxies to unwrap sealed traffic")
	parser.add_argument("--base", required=True, help="domain naming context, e.g. DC=wonka,DC=lab")
	parser.add_argument("--domain-sid", required=True)
	parser.add_argument("--proxy", default="/tmp/pv-ldapx-proxy", help="upstream ldapx binary built from the pinned revision")
	parser.add_argument("--filter", default="CZNDR")
	parser.add_argument("--basedn", default="CX")
	parser.add_argument("--attrlist", default="CR")
	parser.add_argument("--reps", type=int, default=5)
	parser.add_argument("--report", default="/tmp/ldapx_live_ab.json")
	args = parser.parse_args()

	chains = [("-f", args.filter), ("-b", args.basedn), ("-a", args.attrlist)]
	port_log, upstream_log = "/tmp/ldapx_live_port.log", "/tmp/ldapx_live_upstream.log"
	port_proxy = start_proxy(args.proxy, args.dc, 3389, args.password, port_log, [])
	upstream_proxy = start_proxy(args.proxy, args.dc, 3390, args.password, upstream_log, chains)
	via = lambda port: [f"{args.identity}@127.0.0.1", "-p", str(port), "--use-ldap", "-ns", args.dc]
	port_flags = ["--obfuscate", args.filter, "--obfuscate-basedn", args.basedn, "--obfuscate-attrlist", args.attrlist]
	report = []
	try:
		for name, template in QUERIES:
			query = template.format(base=args.base, domain_sid=args.domain_sid)
			baseline, error = run_powerview(f"{args.identity}@{args.dc}", query, [])
			row = {"name": name, "query": query, "baseline": None if baseline is None else len(baseline), "baseline_error": error}
			for mode, port, log_path, extra in (("port", 3389, port_log, port_flags), ("upstream", 3390, upstream_log, [])):
				row[mode] = []
				for _ in range(args.reps):
					offset = os.path.getsize(log_path)
					results, error = run_powerview(via(port)[0], query, via(port)[1:] + extra)
					time.sleep(0.15)
					row[mode].append({
						"count": None if results is None else len(results),
						"same": None if results is None or baseline is None else results == baseline,
						"error": error,
						"wire": wire_searches(log_path, offset),
					})
			report.append(row)
			summary = "  ".join("%s %d/%d" % (mode, sum(1 for run in row[mode] if run["same"]), args.reps) for mode in ("port", "upstream"))
			print(f"[{name}] baseline={row['baseline']}  {summary}", flush=True)
	finally:
		for process in (port_proxy, upstream_proxy):
			os.killpg(process.pid, signal.SIGTERM)

	print("\nWire metrics (every search request the DC received)")
	for mode in ("port", "upstream"):
		searches = [search for row in report for run in row[mode] for search in run["wire"]]
		print(f"  {mode:9}", "  ".join(f"{key}={value:.2f}" if isinstance(value, float) else f"{key}={value}" for key, value in wire_metrics(searches).items()))
	Path(args.report).write_text(json.dumps(report, indent=1))
	print(f"\nfull report: {args.report}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
