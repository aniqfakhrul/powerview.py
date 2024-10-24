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

import ldap3
import json
import re
import logging
import base64
import datetime
from tabulate import tabulate as table

class FORMATTER:
    def __init__(self, pv_args, use_kerberos=False):
        self.__newline = '\n'
        self.args = pv_args
        self.use_kerberos = use_kerberos

    def count(self, entries):
        print(len(entries))

    def print_table(self, entries: list, headers: list, align: str = None):
        filtered_entries = [entry for entry in entries if not all(e == '' for e in entry)]
        print()
        table_res = table(
            filtered_entries,
            headers,
            numalign="left" if not align else align
            )
        if self.args.outfile:
            LOG.write_to_file(self.args.outfile, table_res)
        print(table_res)
        print()

    def print_index(self, entries):
        i = int(self.args.select)
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

                    value = self.beautify(value,self.get_max_len(list(entry['attributes'].keys()))+2)
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
                        _stdout = f"{attr.ljust(28)}: {value}"
                        if self.args.outfile:
                            LOG.write_to_file(self.args.outfile, _stdout)
                        print(_stdout)
                    if self.args.outfile:
                        LOG.write_to_file(self.args.outfile, "")
                    print()

    def print_select(self,entries):
        select_attributes = self.args.select.split(",")
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
                            if len(value) != 0:
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
                                    _stdout = f"{key.ljust(28)}: {ace[key]}"
                                    if self.args.outfile:
                                        LOG.write_to_file(self.args.outfile, _stdout)
                                    print(_stdout)
                    if len(select_attributes) != 1:
                        if self.args.outfile:
                            LOG.write_to_file(self.args.outfile, "")
                        print()

    def table_view(self, entries):
        headers = []
        rows = []
        nested_list = False
        if (hasattr(self.args, "select") and self.args.select) or (hasattr(self.args, "properties") and self.args.properties and not self.args.properties == '*'):
            if self.args.select:
                headers = self.args.select.split(",")
            elif self.args.properties:
                headers = self.args.properties.split(",")
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
                        if isinstance(val,list):
                            temp = ""
                            for attr in val:
                                if isinstance(attr, bytes):
                                    temp += base64.b64encode(attr).decode("utf-8") + "\n"
                                elif isinstance(attr, int):
                                    temp = str(attr)
                                elif isinstance(attr, datetime.datetime):
                                    temp = str(attr.strftime('%m/%d/%Y'))
                                else:
                                    temp += attr + "\n"
                            val = temp
                        elif isinstance(val, int):
                            val = str(val)
                        elif isinstance(val, bytes):
                            val = base64.b64encode(val).decode("utf-8")
                        elif isinstance(val, datetime.datetime):
                            val = str(val.strftime('%m/%d/%Y'))

                        row.append(
                                val 
                                )
                    rows.append(row)
        else:
            for entry in entries:
                row = []
                for head in headers:
                    val = IDict(entry["attributes"]).get(head) # IDict give get() with case-insensitive capabilities :)

                    if isinstance(val,list):
                        temp = ""
                        for attr in val:
                            if isinstance(attr, bytes):
                                temp += base64.b64encode(attr).decode("utf-8") + "\n"
                            elif isinstance(attr, int):
                                temp = str(attr)
                            elif isinstance(attr, datetime.datetime):
                                temp = str(attr.strftime('%m/%d/%Y'))
                            else:
                                temp += attr + "\n"
                        val = temp
                    elif isinstance(val, int):
                        val = str(val)
                    elif isinstance(val, bytes):
                        val = base64.b64encode(val).decode("utf-8")
                    elif isinstance(val, datetime.datetime):
                        val = str(val.strftime('%m/%d/%Y'))

                    row.append(
                            val 
                            )

                rows.append(row)

        self.print_table(entries=rows, headers=headers)

    def print(self,entries):
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

                    value = self.beautify(value,self.get_max_len(list(entry['attributes'].keys()))+2)

                    if isinstance(value,list):
                        if len(value) != 0:
                            value = self.clean_value(value)

                            have_entry = True
                            _stdout = f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(self.get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}"
                            if self.args.outfile:
                                LOG.write_to_file(self.args.outfile, _stdout)
                            print(_stdout)
                    else:
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
                        _stdout = f'{k.ljust(28)}: {v}'
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
        return len(max(lst,key=len)) + 5

    def clean_value(self, value):
        temp = []
        for i in range(len(value)):
            if isinstance(value[i], list):
                temp += value[i]
            else:
                temp.append(value[i])
        
        return temp

    def beautify(self, strs,lens):
        if isinstance(strs,str) and not self.args.nowrap:
            temp = ""
            if len(strs) > 100:
                index = 100
                for i in range(0,len(strs),100):
                    temp += f"{str(strs[i:index])}\n"
                    temp += ''.ljust(lens)
                    index+=100
            else:
                temp = f"{str(strs).ljust(lens)}"

            return temp.strip()
        elif isinstance(strs, list) and not self.args.nowrap:
            for i in range(len(strs)):
                if isinstance(strs[i], datetime.datetime):
                    strs[i] = strs[i].strftime('%m/%d/%Y')
                elif isinstance(strs[i], bytes):
                    strs[i] = base64.b64encode(strs[i]).decode('utf-8')
                    temp = ""
                    if len(strs[i]) > 100:
                        index = 100
                        for j in range(0,len(strs[i]),100):
                            temp += f"{str(strs[i][j:index])}\n"
                            temp += ''.ljust(lens)
                            index+=100
                    else:
                        temp = f"{str(strs[i]).ljust(lens)}"

                    strs[i] = temp.strip()
            return strs
        elif isinstance(strs, bytes):
            strs = base64.b64encode(strs).decode("utf-8")
            return strs
        else:
            return str(strs)
