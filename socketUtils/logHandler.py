#!/usr/bin/env python3

import logging
import sys
from datetime import datetime
from pathlib import Path

DEBUG = 10
INFO = 20
WARN = 30
WARNING = 30
ERROR = 40
CRITICAL = 50

class CustomTimeFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3]

class CustomColorFormatter(logging.Formatter):
    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = CustomTimeFormatter(log_fmt)
        return formatter.format(record)

fmt = f'[ AT "%(asctime)s" IN "%(name)s, %(threadName)s, %(funcName)s()" ] %(message)s'

streamFormatter = CustomColorFormatter(fmt)
fileFormatter = CustomTimeFormatter(fmt)

file_handler = logging.FileHandler(f"{Path(sys.argv[0]).stem}.log", mode="w")
file_handler.setFormatter(fileFormatter)
file_handler.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(streamFormatter)
stream_handler.setLevel(logging.DEBUG)

def getSimpleLogger(name, streamLogLevel=False, fileLogLevel=False):
    fmt = f'[ AT "%(asctime)s" IN "%(name)s, %(threadName)s, %(funcName)s()" ] %(message)s'

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if streamLogLevel:
        handler = logging.StreamHandler()
        handler.setFormatter(CustomColorFormatter(fmt))
        handler.setLevel(streamLogLevel)
        logger.addHandler(handler)

    if fileLogLevel:
        handler = logging.FileHandler(f"{Path(sys.argv[0]).stem}.log", mode="w")
        handler.setFormatter(CustomTimeFormatter(fmt))
        handler.setLevel(fileLogLevel)
        logger.addHandler(handler)

    return logger
