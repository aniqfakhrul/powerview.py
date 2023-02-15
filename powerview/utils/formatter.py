#!/usr/bin/env python3
from powerview.utils.colors import bcolors
from powerview.lib.resolver import (
    UAC,
    ENCRYPTION_TYPE,
    LDAP
)
from powerview import PowerView as PV
from powerview.utils.logging import LOG

import ldap3
import json
import re
import logging
import base64
import datetime

class FORMATTER:
    def __init__(self, pv_args, use_kerberos=False):
        self.__newline = '\n'
        self.args = pv_args
        self.use_kerberos = use_kerberos
        
        print(self.args)

    def count(self, entries):
        print(f"{len(entries)}")

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
                            # write output to file
                            if self.args.outfile:
                                LOG.write_to_file(self.args.outfile, "hehehhee")

                            print(f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(self.get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}")
                    else:
                        print(f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {value}")
                print()
            elif isinstance(entry['attributes'],list):
                entry = self.resolve_values(entry)
                for ace in entry['attributes'][0:i]:
                    for attr, value in ace.items():
                        print(f"{attr.ljust(28)}: {value}")
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
                                    print(value)
                                else:
                                    print(f"{key.ljust(self.get_max_len(select_attributes))}: {value}")
                if len(select_attributes) != 1:
                    print()
            elif isinstance(entry['attributes'], list):
                entry = self.resolve_values(entry)
                for ace in entry['attributes']:
                    for key in list(ace.keys()):
                        for attr in select_attributes:
                            if str(attr).casefold() == str(key).casefold():
                                if len(select_attributes) == 1:
                                    print(ace[key])
                                else:
                                    print(f"{key.ljust(28)}: {ace[key]}")
                    if len(select_attributes) != 1:
                        print()

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
                            have_entry = True
                            print(f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(self.get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}")
                    else:
                        have_entry = True
                        print(f"{attr.ljust(self.get_max_len(list(entry['attributes'].keys())))}: {str(value)}")
                if have_entry:
                    print()
            elif isinstance(entry['attributes'],list):
                entry = self.resolve_values(entry)
                for ace in entry['attributes']:
                    for k, v in ace.items():
                        print(f'{k.ljust(28)}: {v}')
                    print()
            elif isinstance(entry, str):
                entry = self.resolve_values(entry)
                print(entry)

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
        try:
            if "msDS-SupportedEncryptionTypes" in list(entry["attributes"].keys()):
                if isinstance(entry['attributes']['msDS-SupportedEncryptionTypes'], list):
                    entry["attributes"]["msDS-SupportedEncryptionTypes"] = ENCRYPTION_TYPE.parse_value(entry["attributes"]["msDS-SupportedEncryptionTypes"][0])
                else:
                    entry["attributes"]["msDS-SupportedEncryptionTypes"] = ENCRYPTION_TYPE.parse_value(entry["attributes"]["msDS-SupportedEncryptionTypes"])
        except:
            pass

        # resolve userAccountControl
        try:
            if "userAccountControl" in list(entry["attributes"].keys()):
                if isinstance(entry['attributes']['userAccountcontrol'], list):
                    entry["attributes"]["userAccountControl"] = UAC.parse_value(entry["attributes"]["userAccountControl"][0])
                else:
                    entry["attributes"]["userAccountControl"] = UAC.parse_value(entry["attributes"]["userAccountControl"])
        except:
            pass

        return entry

    def get_max_len(self, lst):
        return len(max(lst,key=len)) + 5

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
