#!/usr/bin/env python3
from os import system, name
import json
from powerview.utils.colors import bcolors

# define our clear function
def clear_screen():

    # for windows
    if name == 'nt':
        _ = system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')
