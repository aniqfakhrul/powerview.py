#!/usr/bin/env python3
from powerview.utils.colors import bcolors
from powerview.lib.resolver import (
    UAC,
    ENCRYPTION_TYPE,
    LDAP
)
from powerview import PowerView as PV
from powerview.utils.logging import LOG
from powerview.utils.helpers import IDict, strip_ansi, convert_to_json_serializable
from powerview.utils.constants import TABLE_FMT_MAP

import ldap3
import json
import re
import logging
import base64
import datetime
from tabulate import tabulate as table
from io import StringIO
import csv
from collections.abc import Mapping

class FORMATTER:
    def __init__(self, pv_args, config=None):
        self.__newline = '\n'
        self.args = pv_args
        
        # Default configuration
        self.config = {
            'wrap_length': 100,            # Text wrap length for large values
            'attr_spacing': 28,            # Default attribute name spacing
            'max_entries': 1000,           # Maximum entries before pagination
            'date_format': '%m/%d/%Y %H:%M:%S %p',  # Format for datetime values
            'binary_format': 'base64',     # Format for binary data (base64, hex)
            'padding': 5,                  # Extra padding for attribute names
            'nested_indent': 3,            # Indentation for nested values
            'max_list_items': 100,         # Maximum items to show in lists
            'table_format': 'simple',      # Default table format
            'csv_quote_all': True,         # Quote all CSV fields
            'show_empty_values': False,    # Show attributes with empty values
            'truncate_long_values': True,  # Truncate very long values
            'max_value_length': 1000       # Maximum value length before truncation
        }
        
        # Override with user config if provided
        if config:
            self.config.update(config)
            
        # Initialize format cache
        self._format_cache = {}
        self.last_results_from_cache = False

    def count(self, entries):
        print(len(entries))

    @staticmethod
    def normalize_select(select):
        """Normalise -Select into None | int (row limit) | list[str] (names).

        Most subparsers run the value through Helper.parse_select, but callers
        may still hand us a raw string, so normalise defensively. `is None` is
        used deliberately rather than truthiness: -Select 0 is a real limit
        meaning "no rows", not "no selection".
        """
        if select is None:
            return None
        if isinstance(select, bool):
            return None
        if isinstance(select, int):
            return select
        if isinstance(select, str):
            names = [part.strip() for part in select.split(',') if part.strip()]
            return names or None
        if isinstance(select, (list, tuple)):
            names = [str(part).strip() for part in select if str(part).strip()]
            return names or None
        return None

    @staticmethod
    def slice_entries(entries, limit):
        """Apply an integer -Select as a row limit.

        For ACL results (`attributes` is a list of ACE dicts) the limit applies
        to each entry's ACE list, matching print_index. Wrappers are copied so
        the caller's entries -- which may be shared with the query cache -- are
        never mutated.
        """
        if not isinstance(entries, list):
            return entries
        sliced = []
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("attributes"), list):
                trimmed = dict(entry)
                trimmed["attributes"] = entry["attributes"][:limit]
                sliced.append(trimmed)
            else:
                sliced.append(entry)
        return sliced[:limit]

    @staticmethod
    def normalize_json_result(entries, json_mode):
        """Return a renderable JSON result and whether the command failed.

        Query methods use an empty list for a successful query with no matches,
        while ``None`` means the command could not produce a result (for
        example, because name resolution or an RPC connection failed).  JSON
        callers still receive a valid empty document, and the command loop uses
        the failure marker to return a non-zero status in one-shot mode.
        """
        if json_mode and entries is None:
            return [], True
        return entries, False

    def resolve_table_format(self):
        """Resolve -TableView into a tabulate/handled format name."""
        table_format = self.args.tableview if hasattr(self.args, 'tableview') else self.config['table_format']
        return TABLE_FMT_MAP.get(table_format, "simple")

    def print_table(self, entries: list, headers: list, align: str = None):
        table_format = self.resolve_table_format()

        filtered_entries = [entry for entry in entries if not all(e == '' for e in entry)]
        print()
        if table_format == "json":
            # Flat contract: one object per row, all values already stringified
            # by format_value_by_type(). Strip presentation-only ANSI sequences
            # at the JSON boundary without changing csv/md/html/latex output.
            header_list = list(headers) if headers else []
            rows = []
            for row in filtered_entries:
                rows.append({
                    header_list[i]: strip_ansi(cell)
                    for i, cell in enumerate(row)
                    if i < len(header_list)
                })
            table_res = json.dumps(rows, indent=2, ensure_ascii=False)
        elif table_format == "csv":
            output = StringIO()
            csv_writer = csv.writer(output, quoting=csv.QUOTE_ALL if self.config['csv_quote_all'] else csv.QUOTE_MINIMAL)
            if headers:
                csv_writer.writerow(headers)
            csv_writer.writerows(filtered_entries)
            table_res = output.getvalue()
            output.close()
        else:
            table_res = table(
                filtered_entries,
                headers,
                numalign="left" if not align else align,
                tablefmt=table_format
            )
        if self.args.outfile:
            LOG.write_to_file(self.args.outfile, table_res)
        print(table_res)
        print()

    def _entry_to_json(self, entry):
        """Map one result entry onto its JSON representation.

        Handles every shape the text formatter accepts: ldap3 Entry objects,
        dict / CaseInsensitiveDict attributes, ACL wrappers whose attributes
        are a list of ACE dicts, and bare strings.
        """
        if isinstance(entry, ldap3.abstract.entry.Entry):
            # NOT entry_to_json(): ldap3's format_json() pre-serialises values,
            # rendering datetimes as str() instead of ISO-8601 and wrapping
            # non-UTF-8 bytes in a tagged {"encoded": ...} object. Both break
            # the documented encoding contract, so read the raw values instead.
            return {"dn": entry.entry_dn, "attributes": entry.entry_attributes_as_dict}

        if isinstance(entry, str):
            return entry

        if not isinstance(entry, dict):
            return entry

        result = {"dn": entry.get("dn"), "attributes": entry.get("attributes")}
        if "from_cache" in entry:
            result["from_cache"] = entry["from_cache"]
        return result

    @staticmethod
    def _project_attributes(attributes, names):
        """Select `names` from one attribute mapping, case-insensitively.

        Keys keep the spelling the server returned (sAMAccountName), not the
        spelling typed into -Select, so output is stable regardless of how the
        flag was written.
        """
        lookup = {str(key).casefold(): key for key in attributes.keys()}
        source = IDict(attributes)
        projected = {}
        for name in names:
            actual = lookup.get(str(name).casefold())
            if actual is None:
                continue
            # The key lookup above distinguishes a missing attribute from an
            # explicitly null value. Preserve the latter as JSON null.
            projected[actual] = source.get(name)
        return projected

    def _project_entry(self, entry, names):
        """Project a single entry onto the named attributes, case-insensitively.

        Copies wrappers and ACE dicts: the caller's entries may be shared with
        the query cache and must never be mutated.
        """
        if not isinstance(entry, dict):
            return entry
        attributes = entry.get("attributes")
        if isinstance(attributes, list):
            projected = [self._project_attributes(ace, names)
                         for ace in attributes if isinstance(ace, dict)]
        elif isinstance(attributes, (dict, ldap3.utils.ciDict.CaseInsensitiveDict)):
            projected = self._project_attributes(attributes, names)
        else:
            return entry
        copied = dict(entry)
        copied["attributes"] = projected
        return copied

    def print_json(self, entries):
        """Render results as a single structured JSON document on stdout."""
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            entries = [entries]

        select = self.normalize_select(getattr(self.args, "select", None))
        if isinstance(select, int):
            entries = self.slice_entries(entries, select)

        payload = []
        for entry in entries:
            # Normalise first: _project_entry only understands dicts, so an
            # ldap3 Entry projected before conversion would keep every attribute.
            normalized = self._entry_to_json(entry)
            if isinstance(select, list) and isinstance(normalized, dict):
                normalized = self._project_entry(normalized, select)
            payload.append(normalized)

        # Convert explicitly rather than leaning on json.dumps(default=...):
        # default= is only consulted for types json cannot handle, so a missed
        # bytes value would be str()'d into "b'\x01'" instead of base64.
        payload = convert_to_json_serializable(payload)
        document = json.dumps(payload, indent=2, ensure_ascii=False,
                              default=self._json_fallback)

        if getattr(self.args, "outfile", None):
            # One write for the whole document: LOG.write_to_file appends and
            # adds a newline per call, so per-line writes would emit invalid JSON.
            LOG.write_to_file(self.args.outfile, document)
        print(document)

    @staticmethod
    def _json_fallback(obj):
        """Last-resort guard; convert_to_json_serializable should handle everything."""
        logging.warning("Unserializable value of type %s in JSON output", type(obj).__name__)
        return str(obj)

    WHERE_PATTERN = ' con | cont | conta | contai | contain | contains | eq | equ | equa | equal | match | mat | matc | not | != |!=| = |=C|=D'

    def _emit(self, line=""):
        if getattr(self.args, "outfile", None):
            LOG.write_to_file(self.args.outfile, line)
        print(line)

    def _warn_if_cached(self, entries):
        first = entries[0] if entries else None
        self.last_results_from_cache = isinstance(first, dict) and bool(first.get('from_cache', False))
        if self.last_results_from_cache:
            logging.warning("[Formatter] Results from cache. Use 'Clear-Cache' or '-NoCache' to refresh.")

    @staticmethod
    def _normalize_entry(entry):
        if isinstance(entry, ldap3.abstract.entry.Entry):
            return json.loads(entry.entry_to_json())
        return entry

    @staticmethod
    def _records(entry):
        """Return the attribute mappings of an entry: one per ACE, or the object's own."""
        attributes = entry.get("attributes") if isinstance(entry, dict) else None
        if isinstance(attributes, list):
            return [ace for ace in attributes if isinstance(ace, Mapping)]
        if isinstance(attributes, Mapping):
            return [attributes]
        return []

    @staticmethod
    def _is_acl(entry):
        return isinstance(entry, dict) and isinstance(entry.get("attributes"), list)

    @staticmethod
    def _lookup(record, name):
        wanted = str(name).casefold()
        for key in record.keys():
            if str(key).casefold() == wanted:
                return True, record[key]
        return False, None

    def _width(self, keys):
        return max((len(str(key)) for key in keys), default=0) + self.config['padding']

    def _format_item(self, item):
        if isinstance(item, datetime.datetime):
            return item.strftime(self.config['date_format'])
        if isinstance(item, bytes):
            return self.format_binary_data(item)
        if isinstance(item, Mapping) and "encoded" in item:
            return str(item["encoded"])
        return str(item)

    def _text_items(self, value):
        if isinstance(value, (list, tuple, set)):
            flattened = []
            for item in value:
                flattened.extend(item if isinstance(item, (list, tuple)) else [item])
            return [self._format_item(item) for item in flattened]
        return [self._format_item(value)]

    def _wrap(self, text):
        length = self.config['wrap_length']
        if getattr(self.args, "nowrap", False) or len(text) <= length:
            return [text]
        return [text[index:index + length] for index in range(0, len(text), length)]

    def _lines(self, value, inline=False):
        items = self._text_items(value)
        if inline and isinstance(value, (list, tuple)):
            return [", ".join(items)] if items else []
        return [line for item in items for line in self._wrap(item)]

    def _visible(self, lines):
        return self.config['show_empty_values'] or any(line.strip() for line in lines)

    def _print_record(self, record, width, keys, inline=False):
        printed = False
        for key in keys:
            lines = self._lines(record[key], inline)
            if not self._visible(lines):
                continue
            self._emit(f"{str(key).ljust(width)}: " + f"\n{''.ljust(width + 2)}".join(lines))
            printed = True
        return printed

    def _print_entries(self, entries, names=None):
        wanted = {str(name).casefold() for name in names} if names else None
        for entry in entries:
            entry = self._normalize_entry(entry)
            if isinstance(entry, str):
                self._emit(entry)
                continue
            records = self._records(entry)
            inline = self._is_acl(entry)
            width = self._width(names or [key for record in records for key in record.keys()])
            for record in records:
                keys = [key for key in record.keys() if not wanted or str(key).casefold() in wanted]
                if wanted and len(names) == 1:
                    for key in keys:
                        for line in self._lines(record[key], inline):
                            if self._visible([line]):
                                self._emit(line)
                elif self._print_record(record, width, keys, inline):
                    self._emit()

    def print(self, entries):
        if getattr(self.args, 'paginate', False) and len(entries) > self.config['max_entries']:
            self._print_paginated(entries)
            return
        self._warn_if_cached(entries)
        self._print_entries(entries)

    def print_index(self, entries):
        self._print_entries(self.slice_entries(entries, self.args.select))

    def print_select(self, entries):
        self._print_entries(entries, self.normalize_select(self.args.select))

    def _print_paginated(self, entries):
        self._warn_if_cached(entries)
        page_size = self.config['max_entries']
        total_pages = (len(entries) + page_size - 1) // page_size
        current_page = 1
        while True:
            start = (current_page - 1) * page_size
            end = min(start + page_size, len(entries))
            print(f"\n--- Page {current_page}/{total_pages} (Entries {start + 1}-{end} of {len(entries)}) ---\n")
            self._print_entries(entries[start:end])
            if total_pages <= 1:
                break
            action = input("\nEnter 'n' for next page, 'p' for previous page, 'q' to quit pagination: ").lower()
            if action == 'n' and current_page < total_pages:
                current_page += 1
            elif action == 'p' and current_page > 1:
                current_page -= 1
            elif action == 'q':
                break
            else:
                print("Invalid command or page limit reached.")

    def _cell(self, record, head, inline=False):
        found, value = self._lookup(record, head)
        if not found:
            return ""
        if inline and isinstance(value, (list, tuple)):
            return ", ".join(self._text_items(value))
        return self.format_value_by_type(value)

    def table_view(self, entries):
        self._warn_if_cached(entries)
        select = self.normalize_select(getattr(self.args, "select", None))
        if isinstance(select, int):
            entries = self.slice_entries(entries, select)
        if not entries:
            if self.resolve_table_format() == "json":
                # Route through print_table so -OutFile still receives the
                # single [] document instead of an empty file.
                self.print_table([], [])
            else:
                logging.info("No results found")
            return

        normalized = [self._normalize_entry(entry) for entry in entries]
        records = [(record, self._is_acl(entry)) for entry in normalized for record in self._records(entry)]
        properties = getattr(self.args, "properties", None)
        if isinstance(select, list):
            headers = select
        elif properties and properties != ldap3.ALL_ATTRIBUTES:
            headers = properties
        else:
            headers = list(dict.fromkeys(key for record, _ in records for key in record.keys()))
        rows = [[self._cell(record, head, inline) for head in headers] for record, inline in records]
        self.print_table(entries=rows, headers=headers)

    def _sort_key(self, record, name):
        found, value = self._lookup(record, name)
        items = list(value) if isinstance(value, (list, tuple)) else [value]
        first = items[0] if found and items else None
        if first is None or first == "":
            return (1, 0, "")
        if isinstance(first, (int, float)) and not isinstance(first, bool):
            return (0, first, "")
        if isinstance(first, datetime.datetime):
            return (0, 0, first.isoformat())
        return (0, 0, self._format_item(first).casefold())

    def sort_entries(self, entries, sort_option):
        normalized = [self._normalize_entry(entry) for entry in entries]
        if not any(self._lookup(record, sort_option)[0] for entry in normalized for record in self._records(entry)):
            logging.warning(f"[Formatter] Sort key {sort_option} not found. Skipping...")
            return entries
        if any(isinstance(entry, dict) and isinstance(entry.get("attributes"), list) for entry in normalized):
            sorted_entries = []
            for entry in normalized:
                copied = dict(entry)
                copied["attributes"] = sorted(self._records(entry), key=lambda ace: self._sort_key(ace, sort_option))
                sorted_entries.append(copied)
            return sorted_entries
        order = sorted(range(len(entries)), key=lambda index: self._sort_key((self._records(normalized[index]) or [{}])[0], sort_option))
        return [entries[index] for index in order]

    def _where_test(self, operator, right):
        operator = operator.strip().strip("'\"").strip().lower()
        right = right.casefold()
        if operator in ("not", "!="):
            if right == "null":
                return lambda items: any(item.strip() for item in items)
            return lambda items: right not in items
        if operator == "=" or operator in "equal":
            return lambda items: right in items
        if operator in "contains" or operator in "match":
            return lambda items: any(right in item for item in items)
        return None

    def _where_matches(self, record, name, test):
        found, value = self._lookup(record, name)
        return found and test([item.casefold() for item in self._text_items(value)])

    def alter_entries(self, entries, cond):
        try:
            left, right = re.split(self.WHERE_PATTERN, cond, maxsplit=1, flags=re.IGNORECASE)
            operator = re.search(self.WHERE_PATTERN, cond, re.IGNORECASE).group(0)
        except (ValueError, AttributeError):
            logging.error('Where argument format error. (e.g. "samaccountname contains admin")')
            return
        left = left.strip("'").strip('"').strip()
        right = right.strip("'").strip('"').strip()
        test = self._where_test(operator, right)
        if not test:
            logging.error('Invalid operator')
            return []

        filtered = []
        for entry in entries:
            normalized = self._normalize_entry(entry)
            if isinstance(normalized, dict) and isinstance(normalized.get("attributes"), list):
                copied = dict(normalized)
                copied["attributes"] = [ace for ace in self._records(normalized) if self._where_matches(ace, left, test)]
                filtered.append(copied)
            elif any(self._where_matches(record, left, test) for record in self._records(normalized)):
                filtered.append(entry)
        return filtered

    def format_value_by_type(self, value):
        """Format a value for a table cell; lists become one item per line."""
        if isinstance(value, list):
            return self.format_list_value(value)
        return self._format_item(value)

    def format_binary_data(self, data):
        """Format binary data according to configuration."""
        if self.config['binary_format'] == 'hex':
            return data.hex()
        return base64.b64encode(data).decode('utf-8')

    def format_list_value(self, value_list):
        """Format a list of values consistently."""
        if not value_list:
            return ""
        shown = value_list[:self.config['max_list_items']]
        result = "\n".join(self._text_items(shown))
        if len(value_list) > len(shown):
            result += f"\n... (truncated, {len(shown)} of {len(value_list)} items shown)"
        return result

    @staticmethod
    def format_pool_stats(stats):
        """Format connection pool statistics in a readable format."""
        import time
        
        print(f"\n{bcolors.BOLD}{bcolors.OKBLUE}Connection Pool Statistics{bcolors.ENDC}")
        print("=" * 50)
        
        # Check if we have the new enhanced format or old format
        if 'summary' in stats and 'pools' in stats:
            # New enhanced format with LDAP and SMB pools
            summary = stats['summary']
            pools = stats['pools']
            
            # Overall statistics
            print(f"{bcolors.BOLD}Pool Overview:{bcolors.ENDC}")
            print(f"  Total Connections: {bcolors.OKGREEN}{summary['total_connections']}{bcolors.ENDC}")
            print(f"  Maximum Allowed:   {bcolors.WARNING}{summary['total_max_connections']}{bcolors.ENDC}")
            print(f"  Failed Attempts:   {bcolors.FAIL if summary['total_failed_attempts'] > 0 else bcolors.OKGREEN}{summary['total_failed_attempts']}{bcolors.ENDC}")
            
            if summary['total_max_connections'] > 0:
                utilization = (summary['total_connections'] / summary['total_max_connections']) * 100
                utilization_color = bcolors.OKGREEN if utilization < 70 else bcolors.WARNING if utilization < 90 else bcolors.FAIL
                print(f"  Pool Utilization:  {utilization_color}{utilization:.1f}%{bcolors.ENDC}")
            
            print(f"  LDAP Domains:      {bcolors.OKCYAN}{summary['ldap_domains']}{bcolors.ENDC}")
            print(f"  SMB Hosts:         {bcolors.OKCYAN}{summary['smb_hosts']}{bcolors.ENDC}")
            
            # LDAP Pool Details
            if 'ldap' in pools and pools['ldap'].get('total_connections', 0) > 0:
                ldap_pool = pools['ldap']
                print(f"\n{bcolors.BOLD}{bcolors.OKBLUE}LDAP Connection Pool:{bcolors.ENDC}")
                print("-" * 50)
                print(f"  Connections: {bcolors.OKGREEN}{ldap_pool['total_connections']}{bcolors.ENDC}/{bcolors.WARNING}{ldap_pool['max_connections']}{bcolors.ENDC}")
                print(f"  Utilization: {bcolors.OKGREEN}{summary['pool_utilization']['ldap']:.1f}%{bcolors.ENDC}")
                print(f"  Failed Attempts: {bcolors.FAIL if ldap_pool['failed_attempts'] > 0 else bcolors.OKGREEN}{ldap_pool['failed_attempts']}{bcolors.ENDC}")
                
                # Domain-specific statistics
                if ldap_pool.get('domains'):
                    print(f"\n  {bcolors.BOLD}Domain Connections:{bcolors.ENDC}")
                    for domain, domain_stats in ldap_pool['domains'].items():
                        FORMATTER._format_connection_details(domain, domain_stats, "Domain")
            
            # SMB Pool Details
            if 'smb' in pools and pools['smb'].get('total_connections', 0) > 0:
                smb_pool = pools['smb']
                print(f"\n{bcolors.BOLD}{bcolors.OKBLUE}SMB Connection Pool:{bcolors.ENDC}")
                print("-" * 50)
                print(f"  Connections: {bcolors.OKGREEN}{smb_pool['total_connections']}{bcolors.ENDC}/{bcolors.WARNING}{smb_pool['max_connections']}{bcolors.ENDC}")
                print(f"  Utilization: {bcolors.OKGREEN}{summary['pool_utilization']['smb']:.1f}%{bcolors.ENDC}")
                print(f"  Failed Attempts: {bcolors.FAIL if smb_pool['failed_attempts'] > 0 else bcolors.OKGREEN}{smb_pool['failed_attempts']}{bcolors.ENDC}")
                
                # Host-specific statistics
                if smb_pool.get('hosts'):
                    print(f"\n  {bcolors.BOLD}Host Connections:{bcolors.ENDC}")
                    for host, host_stats in smb_pool['hosts'].items():
                        FORMATTER._format_connection_details(host, host_stats, "Host")
            
            # Pool Health Summary
            print(f"\n{bcolors.BOLD}Pool Health Summary:{bcolors.ENDC}")
            print("-" * 50)
            
            # LDAP health
            if 'ldap' in pools and pools['ldap'].get('domains'):
                ldap_healthy = sum(1 for d in pools['ldap']['domains'].values() if d.get('is_alive', False))
                ldap_total = len(pools['ldap']['domains'])
                ldap_health = (ldap_healthy / ldap_total * 100) if ldap_total > 0 else 0
                health_color = bcolors.OKGREEN if ldap_health == 100 else bcolors.WARNING if ldap_health >= 50 else bcolors.FAIL
                print(f"  LDAP Health: {health_color}{ldap_health:.1f}%{bcolors.ENDC} ({ldap_healthy}/{ldap_total} domains)")
            
            # SMB health
            if 'smb' in pools and pools['smb'].get('hosts'):
                smb_healthy = sum(1 for h in pools['smb']['hosts'].values() if h.get('is_alive', False))
                smb_total = len(pools['smb']['hosts'])
                smb_health = (smb_healthy / smb_total * 100) if smb_total > 0 else 0
                health_color = bcolors.OKGREEN if smb_health == 100 else bcolors.WARNING if smb_health >= 50 else bcolors.FAIL
                print(f"  SMB Health:  {health_color}{smb_health:.1f}%{bcolors.ENDC} ({smb_healthy}/{smb_total} hosts)")
                
        else:
            # Legacy format compatibility
            print(f"{bcolors.BOLD}Pool Overview:{bcolors.ENDC}")
            print(f"  Total Connections: {bcolors.OKGREEN}{stats.get('total_connections', 0)}{bcolors.ENDC}")
            print(f"  Maximum Allowed:   {bcolors.WARNING}{stats.get('max_connections', 0)}{bcolors.ENDC}")
            print(f"  Failed Attempts:   {bcolors.FAIL if stats.get('failed_attempts', 0) > 0 else bcolors.OKGREEN}{stats.get('failed_attempts', 0)}{bcolors.ENDC}")
            
            if stats.get('max_connections', 0) > 0:
                utilization = (stats.get('total_connections', 0) / stats['max_connections']) * 100
                utilization_color = bcolors.OKGREEN if utilization < 70 else bcolors.WARNING if utilization < 90 else bcolors.FAIL
                print(f"  Pool Utilization:  {utilization_color}{utilization:.1f}%{bcolors.ENDC}")
            
            # Domain-specific statistics for legacy format
            if stats.get('domains'):
                print(f"\n{bcolors.BOLD}Domain Connections:{bcolors.ENDC}")
                print("-" * 50)
                for domain, domain_stats in stats['domains'].items():
                    FORMATTER._format_connection_details(domain, domain_stats, "Domain")
        
        print("\n" + "=" * 50)
        print()

    @staticmethod
    def _format_connection_details(name, stats, connection_type):
        """Format individual connection details (domain or host)."""
        import time
        
        # Format timestamps
        last_used_time = datetime.datetime.fromtimestamp(stats['last_used'])
        last_used_str = last_used_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Calculate time since last use
        time_since_use = time.time() - stats['last_used']
        if time_since_use < 60:
            time_since_str = f"{time_since_use:.1f} seconds ago"
        elif time_since_use < 3600:
            time_since_str = f"{time_since_use/60:.1f} minutes ago"
        else:
            time_since_str = f"{time_since_use/3600:.1f} hours ago"
        
        # Format connection age
        age_seconds = stats['age']
        if age_seconds < 60:
            age_str = f"{age_seconds:.1f} seconds"
        elif age_seconds < 3600:
            age_str = f"{age_seconds/60:.1f} minutes"
        else:
            age_str = f"{age_seconds/3600:.1f} hours"
        
        # Connection status color
        status_color = bcolors.OKGREEN if stats['is_alive'] else bcolors.FAIL
        status_text = "ALIVE" if stats['is_alive'] else "DEAD"
        
        print(f"\n    {bcolors.BOLD}{bcolors.OKCYAN}{connection_type}:{bcolors.ENDC} {name.upper()}")
        print(f"      Status:     {status_color}{status_text}{bcolors.ENDC}")
        print(f"      Use Count:  {stats['use_count']}")
        print(f"      Age:        {age_str}")
        print(f"      Last Used:  {last_used_str} ({time_since_str})")
