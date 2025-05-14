#!/usr/bin/env python3
import os
import logging
from datetime import date
from sys import platform
if platform == "linux" or platform == "linux2":
    import gnureadline as readline
else:
    import readline

DEBUG = 'DEBUG'

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

class HistoryConsole:
    def __init__(self, histfile="~/.powerview/.powerview_history"):
        self.histfile = os.path.expanduser(histfile)
        self.init_history(histfile)

    def init_history(self, histfile=None):
        if not histfile:
            histfile = self.histfile

        try:
            if os.path.exists(histfile):
                readline.read_history_file(histfile)
        except FileNotFoundError:
            logging.error(f"History file not found: {histfile}")
        except IOError as e:
            logging.error(f"Error reading history file {histfile}: {e}")

    def save_history(self, histfile=None):
        if not histfile:
            histfile = self.histfile

        try:
            readline.write_history_file(histfile)
        except IOError as e:
            logging.error(f"Error writing history file {histfile}: {e}")

class LOG:
    def __init__(self, folder_name, root_folder=None):
        if not root_folder:
            if os.name == 'nt':
                self.root_folder = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), "powerview")
            else:
                self.root_folder = os.path.join(os.path.expanduser('~'), ".powerview")
        else:
            self.root_folder = root_folder
        
        self.folder_name = folder_name.lower()

        self.logs_folder = os.path.join(self.root_folder, "logs", self.folder_name)
        
        if not os.path.exists(self.logs_folder):
            self.create_folder()

        self.file_name = "%s.log" % date.today()

        print("Logging directory is set to %s" % (self.logs_folder))

        self.history_file = os.path.join(self.logs_folder, ".powerview_history")
        self.history_console = HistoryConsole(self.history_file)

    def save_history(self):
        self.history_console.save_history()

    def create_folder(self, folder=None):
        folder = folder if folder else self.logs_folder
        return os.makedirs(folder, exist_ok=True)
    
    def setup_logger(self, level=logging.INFO):
        if level == DEBUG:
            level == logging.DEBUG
       
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        file_path = os.path.join(self.logs_folder, self.file_name)
        fileh = logging.FileHandler(file_path, 'a')
        formatter = logging.Formatter('[%(asctime)s] %(name)s %(levelname)s %(message)s')
        fileh.setFormatter(formatter)
        logger.addHandler(fileh)

        fmt = '[%(asctime)s] %(message)s'
        stdout_handler = logging.StreamHandler()
        stdout_handler.setLevel(level)
        stdout_handler.setFormatter(CustomFormatter(fmt))

        logger.addHandler(stdout_handler)
        return logger

    def write(self, file_name, text):
        success = False

        if not os.path.exists(self.root_folder):
            os.makedirs(self.root_folder)

        abspath = os.path.join(self.root_folder, file_name)

        try:
            open(abspath,"a").write(text+"\n")
            success = True
        except IOError as e:
            logging.error(
                "Error writing to %s (%s)" % (
                        abspath,
                        str(e)
                    )
                )
        except FileNotFoundError as e:
            logging.error(
                "Error writing to %s (%s)" % (
                        abspath,
                        str(e)
                    )
                )
        except PermissionError as e:
            logging.error(
                "Error writing to %s (%s)" % (
                        abspath,
                        str(e)
                    )
                )

        return success

    @staticmethod
    def write_to_file(file_name, text):
        success = False

        abspath = os.path.expanduser(file_name)

        try:
            with open(abspath, "a") as f:
                f.write(text + "\n")
                success = True
        except (IOError, FileNotFoundError, PermissionError) as e:
            raise Exception(
                f"Error writing to {abspath} ({str(e)})"
            )

        return success
