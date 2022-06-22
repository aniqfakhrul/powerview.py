#!/usr/bin/env python3
from os import system, name
import json
from pywerview.utils.colors import bcolors

def formatter(pv_args, entries):
    if pv_args.select is not None:
        select_attribute = pv_args.select.split(",")
        if len(select_attribute) == 1:
            print(f"{bcolors.UNDERLINE}{pv_args.select.lower()}{bcolors.ENDC}")
            print()
            for entry in entries:
                entry = json.loads(entry.entry_to_json())
                for key in list(entry["attributes"].keys()):
                    if (pv_args.select.lower() == key.lower()):
                        # Check dictionary in a list
                        for i in entry['attributes'][key]:
                            if (isinstance(i,dict)) and ("encoded" in i.keys()):
                                value = i["encoded"]
                            else:
                                value = str(i)
                        print(value)
        else:
            logging.error(f'{bcolors.FAIL}-select flag can only accept one attribute{bcolors.ENDC}')
    else:
        newline= '\n'
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
                        print(f"{attr.ljust(38)}: {f'{newline.ljust(41)}'.join(value)}")
                else:
                    print(f"{attr.ljust(38)}: {value}")
            print()

# define our clear function
def clear_screen():

    # for windows
    if name == 'nt':
        _ = system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

# define snip function
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
