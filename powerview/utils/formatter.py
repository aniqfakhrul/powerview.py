#!/usr/bin/env python3
from powerview.utils.colors import bcolors
from powerview.lib.resolver import (
    UAC,
    ENCRYPTION_TYPE,
    LDAP
)
from powerview import PowerView as PV
from powerview.utils.logging import LOG
from powerview.utils.helpers import IDict
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

class FORMATTER:
    def __init__(self, pv_args, use_kerberos=False, config=None):
        self.__newline = '\n'
        self.args = pv_args
        self.use_kerberos = use_kerberos
        
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

    def print_table(self, entries: list, headers: list, align: str = None):
        # Use config value with fallback to args
        table_format = self.args.tableview if hasattr(self.args, 'tableview') else self.config['table_format']
        table_format = TABLE_FMT_MAP.get(table_format, "simple")
        
        filtered_entries = [entry for entry in entries if not all(e == '' for e in entry)]
        print()
        if table_format == "csv":
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

    def print_index(self, entries):
        i = self.args.select
        for entry in entries[0:i]:
            if isinstance(entry,ldap3.abstract.entry.Entry) or isinstance(entry['attributes'], dict) or isinstance(entry['attributes'], ldap3.utils.ciDict.CaseInsensitiveDict):
                if isinstance(entry, ldap3.abstract.entry.Entry):
                    entry = json.loads(entry.entry_to_json())
                entry = self.resolve_values(entry)
                for attr,value in entry['attributes'].items():
                    # Check dictionary in a list
                    if isinstance(value, list):
                        for i in value:
                            if (isinstance(i,dict)) and ("encoded" in i.keys()):
                                value = str(i["encoded"])
                            if isinstance(i,int):
                                value = str(i)

                    value = self.beautify(value, self.get_max_len(list(entry['attributes'].keys())) + 2)
                    if isinstance(value,list):
                        if len(value) != 0:
                            value = self.clean_value(value)

                            _stdout = f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(self.get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}"
                            if self.args.outfile:
                                LOG.write_to_file(self.args.outfile, _stdout)
                            print(_stdout)
                    else:
                        _stdout = f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {value}"
                        if self.args.outfile:
                            LOG.write_to_file(self.args.outfile, _stdout)
                        print(_stdout)
                if self.args.outfile:
                    LOG.write_to_file(self.args.outfile, "")
                print()
            elif isinstance(entry['attributes'],list):
                entry = self.resolve_values(entry)
                for ace in entry['attributes'][0:i]:
                    for attr, value in ace.items():
                        _stdout = f"{attr.ljust(self.config['attr_spacing'])}: {value}"
                        if self.args.outfile:
                            LOG.write_to_file(self.args.outfile, _stdout)
                        print(_stdout)
                    if self.args.outfile:
                        LOG.write_to_file(self.args.outfile, "")
                    print()

    def print_select(self,entries):
        select_attributes = self.args.select
        for entry in entries:
            if isinstance(entry,ldap3.abstract.entry.Entry) or isinstance(entry['attributes'], dict) or isinstance(entry['attributes'], ldap3.utils.ciDict.CaseInsensitiveDict):
                if isinstance(entry, ldap3.abstract.entry.Entry):
                    entry = json.loads(entry.entry_to_json())
                entry = self.resolve_values(entry)
                for key in list(entry["attributes"].keys()):
                    for attr in select_attributes:
                        if (str(attr).casefold() == str(key).casefold()):
                            value = ""
                            # Check dictionary in a list
                            if isinstance(entry['attributes'][key], list):
                                entry['attributes'][key] = self.clean_value(entry['attributes'][key])
                                for i in entry['attributes'][key]:
                                    if (isinstance(i,dict)) and ("encoded" in i.keys()):
                                        value = str(i["encoded"])
                                    else:
                                        if len(select_attributes) == 1:
                                            value += str(i)+"\n"
                                        else:
                                            value += str(i)+"\n"+''.ljust(self.get_max_len(select_attributes)+2)
                            else:
                                value = str(entry['attributes'][key])
                            value = value.strip()
                            if len(value) != 0 or self.config['show_empty_values']:
                                if len(select_attributes) == 1:
                                    if self.args.outfile:
                                        LOG.write_to_file(self.args.outfile, value)
                                    print(value)
                                else:
                                    _stdout = f"{key.ljust(self.get_max_len(select_attributes))}: {value}"
                                    if self.args.outfile:
                                        LOG.write_to_file(self.args.outfile, _stdout)
                                    print(_stdout)
                if len(select_attributes) != 1:
                    if self.args.outfile:
                        LOG.write_to_file(self.args.outfile, "")
                    print()
            elif isinstance(entry['attributes'], list):
                entry = self.resolve_values(entry)
                for ace in entry['attributes']:
                    for key in list(ace.keys()):
                        for attr in select_attributes:
                            if str(attr).casefold() == str(key).casefold():
                                if len(select_attributes) == 1:
                                    if self.args.outfile:
                                        LOG.write_to_file(self.args.outfile, ace[key])
                                    print(ace[key])
                                else:
                                    _stdout = f"{key.ljust(self.config['attr_spacing'])}: {ace[key]}"
                                    if self.args.outfile:
                                        LOG.write_to_file(self.args.outfile, _stdout)
                                    print(_stdout)
                    if len(select_attributes) != 1:
                        if self.args.outfile:
                            LOG.write_to_file(self.args.outfile, "")
                        print()

    def table_view(self, entries):
        # Check if results are from cache
        self.last_results_from_cache = False
        if entries and len(entries) > 0:
            # Check first entry for cache status
            first_entry = entries[0]
            if isinstance(first_entry, dict) and first_entry.get('from_cache', False):
                self.last_results_from_cache = True
            
        # Display cache notification if results are from cache
        if self.last_results_from_cache:
            cache_msg = "[Formatter] Results from cache. Use 'Clear-Cache' or '-NoCache' to refresh."
            logging.warning(cache_msg)
        
        headers = []
        rows = []
        nested_list = False
        if (hasattr(self.args, "select") and self.args.select) or (hasattr(self.args, "properties") and self.args.properties and not self.args.properties == '*'):
            if self.args.select:
                headers = self.args.select
            elif self.args.properties:
                headers = self.args.properties
        else:
            if isinstance(entries[0]["attributes"], dict) or isinstance(entries[0]["attributes"], ldap3.utils.ciDict.CaseInsensitiveDict):
                headers = entries[0]["attributes"].keys()
            elif isinstance(entries[0]["attributes"], list):
                headers = entries[0]["attributes"][0].keys()
                nested_list = True

        if isinstance(entries[0]["attributes"], list):
            for entry in entries:
                for ent in entry["attributes"]:
                    row = []
                    for head in headers:
                        val = IDict(ent).get(head) # IDict give get() with case-insensitive capabilities :)
                        val = self.format_value_by_type(val)
                        row.append(val)
                    rows.append(row)
        else:
            for entry in entries:
                row = []
                for head in headers:
                    val = IDict(entry["attributes"]).get(head) # IDict give get() with case-insensitive capabilities :)
                    val = self.format_value_by_type(val)
                    row.append(val)
                rows.append(row)

        self.print_table(entries=rows, headers=headers)

    def print(self, entries):
        # Add pagination for large result sets
        total_entries = len(entries)
        if hasattr(self.args, 'paginate') and self.args.paginate and total_entries > self.config['max_entries']:
            self._print_paginated(entries)
            return
        
        # Check if results are from cache
        self.last_results_from_cache = False
        if entries and len(entries) > 0:
            first_entry = entries[0]
            if isinstance(first_entry, dict) and first_entry.get('from_cache', False):
                self.last_results_from_cache = True
            
        # Display cache notification if results are from cache
        if self.last_results_from_cache:
            cache_msg = "[Formatter] Results from cache. Use 'Clear-Cache' or '-NoCache' to refresh."
            logging.warning(cache_msg)
        
        for entry in entries:
            have_entry = False
            if isinstance(entry,ldap3.abstract.entry.Entry) or isinstance(entry['attributes'], dict) or isinstance(entry['attributes'], ldap3.utils.ciDict.CaseInsensitiveDict):
                if isinstance(entry, ldap3.abstract.entry.Entry):
                    entry = json.loads(entry.entry_to_json())
                entry = self.resolve_values(entry)
                for attr,value in entry['attributes'].items():
                    # Check dictionary in a list
                    if isinstance(value, list):
                        for i in value:
                            if (isinstance(i,dict)) and ("encoded" in i.keys()):
                                value = str(i["encoded"])
                            if isinstance(i,int):
                                value = str(i)

                    value = self.beautify(value, self.get_max_len(list(entry['attributes'].keys()))+2)

                    if isinstance(value,list):
                        if len(value) != 0 or self.config['show_empty_values']:
                            value = self.clean_value(value)

                            have_entry = True
                            _stdout = f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(self.get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}"
                            if self.args.outfile:
                                LOG.write_to_file(self.args.outfile, _stdout)
                            print(_stdout)
                    else:
                        if str(value).strip() != "" or self.config['show_empty_values']:
                            have_entry = True
                            _stdout = f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {str(value)}"
                            if self.args.outfile:
                                LOG.write_to_file(self.args.outfile, _stdout)
                            print(_stdout)
                if have_entry:
                    if self.args.outfile:
                        LOG.write_to_file(self.args.outfile, "")
                    print()
            elif isinstance(entry['attributes'],list):
                entry = self.resolve_values(entry)
                for ace in entry['attributes']:
                    for k, v in ace.items():
                        if str(v).strip() != "" or self.config['show_empty_values']:
                            _stdout = f'{k.ljust(self.config["attr_spacing"])}: {v}'
                            if self.args.outfile:
                                LOG.write_to_file(self.args.outfile, _stdout)
                            print(_stdout)
                    if self.args.outfile:
                        LOG.write_to_file(self.args.outfile, "")
                    print()
            elif isinstance(entry, str):
                entry = self.resolve_values(entry)
                if self.args.outfile:
                    LOG.write_to_file(self.args.outfile, entry)
                print(entry)

    def _print_paginated(self, entries):
        """Print entries with pagination support."""
        # Check if results are from cache
        self.last_results_from_cache = False
        if entries and len(entries) > 0:
            # Check first entry for cache status
            first_entry = entries[0]
            if isinstance(first_entry, dict) and first_entry.get('from_cache', False):
                self.last_results_from_cache = True
            
        # Display cache notification if results are from cache
        if self.last_results_from_cache:
            cache_msg = "[Formatter] Results from cache. Use 'Clear-Cache' or '-NoCache' to refresh."
            logging.warning(cache_msg)
        
        page_size = self.config['max_entries']
        total_pages = (len(entries) + page_size - 1) // page_size
        
        current_page = 1
        while True:
            start_idx = (current_page - 1) * page_size
            end_idx = min(start_idx + page_size, len(entries))
            
            print(f"\n--- Page {current_page}/{total_pages} (Entries {start_idx+1}-{end_idx} of {len(entries)}) ---\n")
            
            # Print current page's entries
            page_entries = entries[start_idx:end_idx]
            for entry in page_entries:
                # Use same logic as print method but for a subset
                have_entry = False
                if isinstance(entry, ldap3.abstract.entry.Entry) or isinstance(entry['attributes'], dict):
                    if isinstance(entry, ldap3.abstract.entry.Entry):
                        entry = json.loads(entry.entry_to_json())
                    entry = self.resolve_values(entry)
                    for attr, value in entry['attributes'].items():
                        value = self.beautify(value, self.get_max_len(list(entry['attributes'].keys()))+2)
                        if isinstance(value, list):
                            if len(value) != 0:
                                value = self.clean_value(value)
                                have_entry = True
                                print(f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(self.get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}")
                        else:
                            have_entry = True
                            print(f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {str(value)}")
                    if have_entry:
                        print()
                elif isinstance(entry['attributes'], list):
                    entry = self.resolve_values(entry)
                    for ace in entry['attributes']:
                        for k, v in ace.items():
                            print(f'{k.ljust(self.config["attr_spacing"])}: {v}')
                        print()
            
            if total_pages <= 1:
                break
                
            # Prompt for next action
            action = input("\nEnter 'n' for next page, 'p' for previous page, 'q' to quit pagination: ").lower()
            if action == 'n' and current_page < total_pages:
                current_page += 1
            elif action == 'p' and current_page > 1:
                current_page -= 1
            elif action == 'q':
                break
            else:
                print("Invalid command or page limit reached.")

    def sort_entries(self, entries, sort_option):
        try:
            def sort_key(entry):
                if sort_option.lower() not in [v.lower() for v in entry["attributes"].keys()]:
                    raise Exception("%s key not found" % (sort_option))

                if not isinstance(entry["attributes"], ldap3.utils.ciDict.CaseInsensitiveDict):
                    entry["attributes"] = IDict(entry["attributes"])

                value = entry['attributes'].get(sort_option)
                if isinstance(value, str):
                    return value.lower()
                elif isinstance(value, list):
                    if sort_option.lower() in ["badpasswordtime", "lastlogoff", "lastlogon", "pwdlastset", "lastlogontimestamp"]:
                        return datetime.datetime.min
                    else:
                        return value
                else:
                    logging.warning("Value not compatible for sorting. Skipping...")
                    return value

            sorted_users = sorted(entries, key=sort_key)
            return sorted_users
        except AttributeError:
            logging.warning("Failed to sort. Probably value is not a string. Skipping...")
            return entries
        except KeyError as e:
            raise KeyError("%s key not found" % str(e))
        finally:
            logging.warning("Failed sort to with unknown error")
            return entries

    def alter_entries(self,entries,cond):
        temp_alter_entries = []
        try:
            left,right = re.split(' con | cont | conta | contai | contain | contains | eq | equ | equa | equal | match | mat | matc | not | != |!=| = |=C|=D', cond, flags=re.IGNORECASE)
            operator = re.search(' con | cont | conta | contai | contain | contains | eq | equ | equa | equal | match | mat | matc | not | != |!=| = |=C|=D', cond, re.IGNORECASE).group(0)
            left = left.strip("'").strip('"').strip()
            operator = operator.strip("'").strip('"').strip()
            right = right.strip("'").strip('"').strip()
        except:
            logging.error('Where argument format error. (e.g. "samaccountname contains admin")')
            return
        if (operator in "contains") or (operator in "match"):
            for entry in entries:
                if isinstance(entry,ldap3.abstract.entry.Entry) or isinstance(entry['attributes'], dict) or isinstance(entry['attributes'], ldap3.utils.ciDict.CaseInsensitiveDict):
                    if isinstance(entry, ldap3.abstract.entry.Entry):
                        temp_entry = json.loads(entry.entry_to_json())
                    else:
                        temp_entry = entry
                    for c in list(temp_entry['attributes'].keys()):
                        if str(c).casefold() == str(left).casefold():
                            left = c
                            break
                    try:
                        if str(right).casefold() in str(temp_entry['attributes'][left]).casefold():
                            temp_alter_entries.append(entry)
                    except KeyError:
                        return None
                elif isinstance(entry['attributes'],list):
                    temp_aces = []
                    for ace in entry['attributes']:
                        for c in list(ace.keys()):
                            if str(c).casefold() == str(left).casefold():
                                left = c
                                break
                        try:
                            if str(right).casefold() in str(ace[left]).casefold():
                                temp_aces.append(ace)
                        except KeyError:
                            pass
                    entry['attributes'] = temp_aces
                    temp_alter_entries.append(entry)

        elif (operator in "equal") or (operator == "="):
            for entry in entries:
                if isinstance(entry,ldap3.abstract.entry.Entry) or isinstance(entry['attributes'], dict) or isinstance(entry['attributes'], ldap3.utils.ciDict.CaseInsensitiveDict):
                    if isinstance(entry, ldap3.abstract.entry.Entry):
                        temp_entry = json.loads(entry.entry_to_json())
                    else:
                        temp_entry = entry
                    for c in list(temp_entry['attributes'].keys()):
                        if str(c).casefold() == str(left).casefold():
                            left = c
                            break
                    try:
                        if str(right).casefold() == str(temp_entry['attributes'][left]).casefold():
                            temp_alter_entries.append(entry)
                    except KeyError:
                        pass
                elif isinstance(entry['attributes'],list):
                    temp_aces = []
                    for ace in entry['attributes']:
                        for c in list(ace.keys()):
                            if str(c).casefold() == str(left).casefold():
                                left = c
                                break
                        try:
                            if str(right).casefold() == str(ace[left]).casefold():
                                temp_aces.append(ace)
                        except KeyError:
                            pass
                    entry['attributes'] = temp_aces
                    temp_alter_entries.append(entry)
        elif (operator.lower() == "not") or (operator.lower() == "!="):
            for entry in entries:
                if isinstance(entry,ldap3.abstract.entry.Entry) or isinstance(entry['attributes'], dict) or isinstance(entry['attributes'], ldap3.utils.ciDict.CaseInsensitiveDict):
                    if isinstance(entry, ldap3.abstract.entry.Entry):
                        temp_entry = json.loads(entry.entry_to_json())
                    else:
                        temp_entry = entry
                    for c in list(temp_entry['attributes'].keys()):
                        if str(c).casefold() == str(left).casefold():
                            left = c
                            break
                    try:
                        if not (len(str(''.join(temp_entry['attributes'][left])).casefold()) == 0) and (str(right).casefold() == "null"):
                            temp_alter_entries.append(entry)
                        elif str(''.join(temp_entry['attributes'][left])).casefold() != str(right).casefold():
                            temp_alter_entries.append(entry)
                    except KeyError:
                        pass
                elif isinstance(entry['attributes'],list):
                    temp_aces = []
                    for ace in entry['attributes']:
                        for c in list(ace.keys()):
                            if str(c).casefold() == str(left).casefold():
                                left = c
                                break
                        try:
                            if str(right).casefold() != str(ace[left]).casefold():
                                temp_aces.append(ace)
                        except KeyError:
                            pass
                    entry['attributes'] = temp_aces
                    temp_alter_entries.append(entry)
        else:
            logging.error(f'Invalid operator')

        return temp_alter_entries

    def resolve_values(self,entry):
        # resolve msDS-SupportedEncryptionTypes
        #try:
        #    if "msDS-SupportedEncryptionTypes" in list(entry["attributes"].keys()):
        #        if isinstance(entry['attributes']['msDS-SupportedEncryptionTypes'], list):
        #            entry["attributes"]["msDS-SupportedEncryptionTypes"] = ENCRYPTION_TYPE.parse_value(entry["attributes"]["msDS-SupportedEncryptionTypes"][0])
        #        else:
        #            entry["attributes"]["msDS-SupportedEncryptionTypes"] = ENCRYPTION_TYPE.parse_value(entry["attributes"]["msDS-SupportedEncryptionTypes"])
        #except:
        #    pass

        #        # resolve userAccountControl
        #        try:
        #            if "userAccountControl" in list(entry["attributes"].keys()):
        #                if isinstance(entry['attributes']['userAccountcontrol'], list):
        #                    entry["attributes"]["userAccountControl"] = UAC.parse_value(entry['attributes']['userAccountControl'][0])
        #                else:
        #                    entry["attributes"]["userAccountControl"] = UAC.parse_value(entry["attributes"]["userAccountControl"])
        #        except:
        #            pass

        return entry

    def get_max_len(self, lst):
        # Cache the result based on list content hash
        cache_key = hash(tuple(sorted(lst)))
        if cache_key in self._format_cache:
            return self._format_cache[cache_key]
        
        result = len(max(lst, key=len)) + self.config['padding']
        self._format_cache[cache_key] = result
        return result

    def clean_value(self, value):
        temp = []
        for i in range(len(value)):
            if isinstance(value[i], list):
                temp += value[i]
            else:
                temp.append(value[i])
        
        return temp

    def beautify(self, strs, lens):
        if isinstance(strs, str) and not self.args.nowrap:
            temp = ""
            if len(strs) > self.config['wrap_length']:
                index = self.config['wrap_length']
                for i in range(0, len(strs), self.config['wrap_length']):
                    temp += f"{str(strs[i:index])}\n"
                    temp += ''.ljust(lens)
                    index += self.config['wrap_length']
            else:
                temp = f"{str(strs).ljust(lens)}"

            return temp.strip()
        elif isinstance(strs, list) and not self.args.nowrap:
            for i in range(len(strs)):
                if isinstance(strs[i], datetime.datetime):
                    strs[i] = strs[i].strftime(self.config['date_format'])
                elif isinstance(strs[i], bytes):
                    strs[i] = self.format_binary_data(strs[i])
                    temp = ""
                    if len(strs[i]) > self.config['wrap_length']:
                        index = self.config['wrap_length']
                        for j in range(0, len(strs[i]), self.config['wrap_length']):
                            temp += f"{str(strs[i][j:index])}\n"
                            temp += ''.ljust(lens)
                            index += self.config['wrap_length']
                    else:
                        temp = f"{str(strs[i]).ljust(lens)}"

                    strs[i] = temp.strip()
            return strs
        elif isinstance(strs, bytes):
            strs = self.format_binary_data(strs)
            return strs
        else:
            return str(strs)

    def format_value_by_type(self, value):
        """Format a value based on its data type."""
        if isinstance(value, datetime.datetime):
            return value.strftime(self.config['date_format'])
        elif isinstance(value, bytes):
            return self.format_binary_data(value)
        elif isinstance(value, list):
            return self.format_list_value(value)
        elif isinstance(value, int):
            return str(value)
        else:
            return str(value)
            
    def format_binary_data(self, data):
        """Format binary data according to configuration."""
        if self.config['binary_format'] == 'base64':
            return base64.b64encode(data).decode('utf-8')
        elif self.config['binary_format'] == 'hex':
            return data.hex()
        else:
            return base64.b64encode(data).decode('utf-8')
            
    def format_list_value(self, value_list):
        """Format a list of values consistently."""
        if not value_list:
            return ""
            
        # Limit list size if needed
        if len(value_list) > self.config['max_list_items']:
            value_list = value_list[:self.config['max_list_items']]
            was_truncated = True
        else:
            was_truncated = False
            
        # Format each element
        formatted_items = []
        for item in value_list:
            if isinstance(item, datetime.datetime):
                formatted_items.append(item.strftime(self.config['date_format']))
            elif isinstance(item, bytes):
                formatted_items.append(self.format_binary_data(item))
            elif isinstance(item, dict) and "encoded" in item:
                formatted_items.append(str(item["encoded"]))
            else:
                formatted_items.append(str(item))
                
        # Join items
        result = "\n".join(formatted_items)
        
        # Add truncation indicator if needed
        if was_truncated:
            result += f"\n... (truncated, {len(value_list)} of {len(value_list)} items shown)"
            
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
