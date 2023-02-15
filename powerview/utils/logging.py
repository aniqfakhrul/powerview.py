#!/usr/bin/env python3
import os
import logging

class LOG:
    def __init__(self, folder_name, root_folder=None):
        folder_name = os.path.join("dumps", folder_name)
        if not root_folder:
            self.root_folder = os.path.dirname(os.path.abspath(__file__))
        else:
            self.root_folder = root_folder

        self.root_folder = os.path.join(self.root_folder, folder_name)

    def write(self, file_name, text):
        if not os.path.exists(self.root_folder):
            os.makedirs(self.root_folder)

        abspath = os.path.join(self.root_folder, file_name)        

        try:
            open(abspath,"w").write(text)
        except IOError as e:
            logging.error(
                "Error writing to %s (%s)" % (
                        abspath,
                        str(e)
                    )
                )

            logging.debug(
                    "Log written to %s" % (
                        abspath 
                    )
                )

    @staticmethod
    def write_to_file(file_name, text):
        try:
            open(file_name, "w").write(text)
        except IOError as e:
            logging.error(
                "Error writing to %s (%s)" % (
                        file_name,
                        str(e)
                    )
                )

            logging.debug(
                    "Log written to %s" % (
                        file_name
                    )
                )
