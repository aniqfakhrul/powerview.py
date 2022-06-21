#!/usr/bin/env python3
from os import system, name

# define our clear function
def clear_screen():

    # for windows
    if name == 'nt':
        _ = system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

# define snip function
def snipping(strs):
    temp = ""
    if len(strs) > 100:
        index = 100
        for i in range(0,len(strs),100):
            temp += f"{str(strs[i:index])}\n"
            temp += ''.ljust(45)
            index+=100
    else:
        temp = f"{str(strs).ljust(45)}"

    return temp.strip()
