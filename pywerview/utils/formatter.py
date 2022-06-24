#!/usr/bin/env python3
from pywerview.utils.colors import bcolors

import json

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
