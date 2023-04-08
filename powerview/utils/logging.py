#!/usr/bin/env python3
import os
import logging

def setup_logger(level=logging.INFO):
    # logger properties
    if level == "DEBUG":
        level == logging.DEBUG
    logger = logging.getLogger()
    logger.setLevel(level)
    fmt = '[%(asctime)s] %(message)s'

    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(level)
    stdout_handler.setFormatter(CustomFormatter(fmt))

    logger.addHandler(stdout_handler)
    return logger

class CustomFormatter(logging.Formatter):
    grey = '\033[2;37m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    bold_red = '\x1b[31;1m'
    reset = '\033[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.green + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

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
            open(abspath,"a").write(text+"\n")
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
            open(file_name, "a").write(text+"\n")
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
