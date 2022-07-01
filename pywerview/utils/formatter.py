#!/usr/bin/env python3
from pywerview.utils.colors import bcolors

import ldap3
import json
import re
import logging

class FORMATTER:
    def __init__(self, pv_args):
        self.__newline = '\n'
        self.args = pv_args

    def print_index(self, entries):
        i = int(self.args.select)
        for entry in entries[0:i]:
            if isinstance(entry,ldap3.abstract.entry.Entry):
                entry = json.loads(entry.entry_to_json())
                for attr,value in entry['attributes'].items():
                    # Check dictionary in a list
                    for i in value:
                        if (isinstance(i,dict)) and ("encoded" in i.keys()):
                            value = i["encoded"]
                        if isinstance(i,int):
                            value = str(i)

                    value = beautify(value,get_max_len(list(entry['attributes'].keys()))+2)
                    if isinstance(value,list):
                        if len(value) != 0:
                            print(f"{attr.ljust(get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}")
                    else:
                        print(f"{attr.ljust(get_max_len(list(entry['attributes'].keys())))}: {value}")
                print()
            elif isinstance(entry['attributes'],list):
                for ace in entry['attributes'][0:i]:
                    for attr, value in ace.items():
                        print(f"{attr.ljust(28)}: {value}")
                    print()

    def print_select(self,entries):
        select_attributes = self.args.select.split(",")
        for entry in entries:
            if isinstance(entry,ldap3.abstract.entry.Entry):
                entry = json.loads(entry.entry_to_json())
                for key in list(entry["attributes"].keys()):
                    for attr in select_attributes:
                        if (attr.casefold() == key.casefold()):
                            value = ""
                            # Check dictionary in a list
                            for i in entry['attributes'][key]:
                                if (isinstance(i,dict)) and ("encoded" in i.keys()):
                                    value = i["encoded"]
                                else:
                                    if len(select_attributes) == 1:
                                        value += str(i)+"\n"
                                    else:
                                        value += str(i)+"\n"+''.ljust(get_max_len(select_attributes)+2)
                            value = value.strip()
                            if len(select_attributes) == 1:
                                print(value)
                            else:
                                print(f"{key.ljust(get_max_len(select_attributes))}: {value}")
                if len(select_attributes) != 1:
                    print()
            elif isinstance(entry['attributes'], list):
                for ace in entry['attributes']:
                    for key in list(ace.keys()):
                        for attr in select_attributes:
                            if attr.casefold() == key.casefold():
                                if len(select_attributes) == 1:
                                    print(ace[key])
                                else:
                                    print(f"{key.ljust(28)}: {ace[key]}")
                    if len(select_attributes) != 1:
                        print()

    def print(self,entries):
        for entry in entries:
            if isinstance(entry,ldap3.abstract.entry.Entry):
                entry = json.loads(entry.entry_to_json())
                for attr,value in entry['attributes'].items():
                    # Check dictionary in a list
                    for i in value:
                        if (isinstance(i,dict)) and ("encoded" in i.keys()):
                            value = i["encoded"]
                        if isinstance(i,int):
                            value = str(i)

                    value = beautify(value,get_max_len(list(entry['attributes'].keys()))+2)
                    if isinstance(value,list):
                        if len(value) != 0:
                            print(f"{attr.ljust(get_max_len(list(entry['attributes'].keys())))}: {f'''{self.__newline.ljust(get_max_len(list(entry['attributes'].keys()))+3)}'''.join(value)}")
                    else:
                        print(f"{attr.ljust(get_max_len(list(entry['attributes'].keys())))}: {value}")
                print()
            elif isinstance(entry['attributes'],list):
                for ace in entry['attributes']:
                    for k, v in ace.items():
                        print(f'{k.ljust(28)}: {v}')
                    print()

    def alter_entries(self,entries,cond):
        temp_alter_entries = []
        try:
            left,right = re.split(' con | cont | conta | contai | contain | contains | eq | equ | equa | equal | match | mat | matc | not | = | != ', cond, flags=re.IGNORECASE)
            operator = re.search(' con | cont | conta | contai | contain | contains | eq | equ | equa | equal | match | mat | matc | not | = | != ', cond, re.IGNORECASE).group(0)
            left = left.strip()
            operator = operator.strip()
            right = right.strip()
        except:
            logging.error('Where argument format error. (e.g. "samaccountname contains admin")')
        if (operator in "contains") or (operator in "match"):
            for entry in entries:
                if isinstance(entry,ldap3.abstract.entry.Entry):
                    temp_entry = json.loads(entry.entry_to_json())
                    for c in list(temp_entry['attributes'].keys()):
                        if c.casefold() == left.casefold():
                            left = c
                            break
                    try:
                        if right.casefold() in temp_entry['attributes'][left][0].casefold():
                            temp_alter_entries.append(entry)
                    except KeyError:
                        return None
                elif isinstance(entry['attributes'],list):
                    temp_aces = []
                    for ace in entry['attributes']:
                        for c in list(ace.keys()):
                            if c.casefold() == left.casefold():
                                left = c
                                break
                        try:
                            if right.casefold() in ace[left].casefold():
                                temp_aces.append(ace)
                        except KeyError:
                            pass
                    entry['attributes'] = temp_aces
                    temp_alter_entries.append(entry)

        elif (operator in "equal") or (operator == "="):
            for entry in entries:
                if isinstance(entry,ldap3.abstract.entry.Entry):
                    temp_entry = json.loads(entry.entry_to_json())
                    for c in list(temp_entry['attributes'].keys()):
                        if c.casefold() == left.casefold():
                            left = c
                            break
                    try:
                        if right.casefold() == temp_entry['attributes'][left][0].casefold():
                            temp_alter_entries.append(entry)
                    except KeyError:
                        pass
                elif isinstance(entry['attributes'],list):
                    temp_aces = []
                    for ace in entry['attributes']:
                        for c in list(ace.keys()):
                            if c.casefold() == left.casefold():
                                left = c
                                break
                        try:
                            if right.casefold() == ace[left].casefold():
                                temp_aces.append(ace)
                        except KeyError:
                            pass
                    entry['attributes'] = temp_aces
                    temp_alter_entries.append(entry)
        elif (operator.lower() == "not") or (operator.lower() == "!="):
            for entry in entries:
                if isinstance(entry,ldap3.abstract.entry.Entry):
                    temp_entry = json.loads(entry.entry_to_json())
                    for c in list(temp_entry['attributes'].keys()):
                        if c.casefold() == left.casefold():
                            left = c
                            break
                    try:
                        if not (len(temp_entry['attributes'][left][0].casefold()) == 0) and (right.casefold() == "null"):
                            temp_alter_entries.append(entry)
                        elif temp_entry['attributes'][left][0].casefold() != right.casefold():
                            temp_alter_entries.append(entry)
                    except KeyError:
                        pass
                elif isinstance(entry['attributes'],list):
                    temp_aces = []
                    for ace in entry['attributes']:
                        for c in list(ace.keys()):
                            if c.casefold() == left.casefold():
                                left = c
                                break
                        try:
                            if right.casefold() != ace[left].casefold():
                                temp_aces.append(ace)
                        except KeyError:
                            pass
                    entry['attributes'] = temp_aces
                    temp_alter_entries.append(entry)
        else:
            logging.error(f'Invalid operator')

        return temp_alter_entries
    
def get_max_len(lst):
    return len(max(lst,key=len)) + 5

def beautify(strs,lens):
    if not isinstance(strs,list):
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
    else:
        return strs
