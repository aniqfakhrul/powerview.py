#!/usr/bin/env python3
from pywerview.utils.colors import bcolors

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

    def print_select(self,entries):
        select_attribute = self.args.select.split(",")
        if len(select_attribute) == 1:
            print(f"{bcolors.UNDERLINE}{self.args.select.lower()}{bcolors.ENDC}")
            print()
            for entry in entries:
                entry = json.loads(entry.entry_to_json())
                for key in list(entry["attributes"].keys()):
                    if (self.args.select.lower() == key.lower()):
                        # Check dictionary in a list
                        for i in entry['attributes'][key]:
                            if (isinstance(i,dict)) and ("encoded" in i.keys()):
                                value = i["encoded"]
                            value = str(i)
                        print(value)
        else:
            logging.error(f'{bcolors.FAIL}-select flag can only accept one attribute{bcolors.ENDC}')

    def print(self,entries):
        for entry in entries:
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
