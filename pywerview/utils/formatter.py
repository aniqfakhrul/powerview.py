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

                    value = beautify(value)
                    if isinstance(value,list):
                        if len(value) != 0:
                            print(f"{attr.ljust(38)}: {f'{self.__newline.ljust(41)}'.join(value)}")
                    else:
                        print(f"{attr.ljust(38)}: {value}")
                print()
            elif isinstance(entry['attributes'],list):
                for ace in entry['attributes'][0:i]:
                    for attr, value in ace.items():
                        value = beautify(value)
                        print(f"{attr.ljust(38)}: {value}")
                    print()

    def print_select(self,entries):
        select_attributes = self.args.select.split(",")
        for entry in entries:
            if isinstance(entry,ldap3.abstract.entry.Entry):
                entry = json.loads(entry.entry_to_json())
                for key in list(entry["attributes"].keys()):
                    for attr in select_attributes:
                        if (attr.casefold() == key.casefold()):
                            # Check dictionary in a list
                            for i in entry['attributes'][key]:
                                if (isinstance(i,dict)) and ("encoded" in i.keys()):
                                    value = i["encoded"]
                                value = str(i)
                            if len(select_attributes) == 1:
                                print(value)
                            else:
                                print(f"{attr.ljust(25)}: {value}")
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
                                    print(f"{key.ljust(25)}: {ace[key]}")
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

                    value = beautify(value)
                    if isinstance(value,list):
                        if len(value) != 0:
                            print(f"{attr.ljust(38)}: {f'{self.__newline.ljust(41)}'.join(value)}")
                    else:
                        print(f"{attr.ljust(38)}: {value}")
                print()
            elif isinstance(entry['attributes'],list):
                for ace in entry['attributes']:
                    for k, v in ace.items():
                        print(f'{k.ljust(30)}: {v}')
                    print()

    def alter_entries(self,entries,cond):
        temp_alter_entries = []
        left,operator,right = cond.split()
        if (operator in "contains") or (operator in "match"):
            for entry in entries:
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

        elif (operator in "equal") or (operator == "="):
            for entry in entries:
                temp_entry = json.loads(entry.entry_to_json())
                for c in list(temp_entry['attributes'].keys()):
                    if c.casefold() == left.casefold():
                        left = c
                        break
                try:
                    if right.casefold() == temp_entry['attributes'][left][0].casefold():
                        temp_alter_entries.append(entry)
                except KeyError:
                    return None
        elif (operator.lower() == "not") or (operator.lower() == "!="):
            for entry in entries:
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
                    return None
        else:
            logging.error(f'Invalid operator')

        return temp_alter_entries

def beautify(strs):
    if not isinstance(strs,list):
        temp = ""
        if len(strs) > 100:
            index = 100
            for i in range(0,len(strs),100):
                temp += f"{str(strs[i:index])}\n"
                temp += ''.ljust(40)
                index+=100
        else:
            temp = f"{str(strs).ljust(40)}"

        return temp.strip()
    else:
        return strs
