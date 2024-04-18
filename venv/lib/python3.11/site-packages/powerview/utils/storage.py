#!/usr/bin/env python3
import json
import os

from powerview.utils.helpers import convert_to_json_serializable

class Storage:
    def __init__(self):
        self.root_folder = ""
       
        try:
            self.root_folder = os.path.join(os.path.expanduser('~'), ".powerview", "storage")
            if not os.path.exists(self.root_folder):
                os.makedirs(self.root_folder, exist_ok=True)
        except:
            pass

    def write_to_file(self, file_name, data: dict):
        raw = {}

        if not file_name.endswith(".json"):
            file_name = "%s.json" % (file_name)
        
        file_path = os.path.join(self.root_folder, file_name)

        # verify data
        if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
            with open(file_path, 'r') as f:
                raw = json.loads(f)
        print(data) 
        with open(file_path, 'a') as file:
            json.dump(data, file, indent=4, default=convert_to_json_serializable)
