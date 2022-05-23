#!/usr/bin/env python3

import logging
import sys
from datetime import datetime

formatter = logging.Formatter(f'[ AT "{datetime.now().strftime("%H:%M:%S.%f")[:-3]}" IN "%(name)s" ] %(message)s')

file_handler = logging.FileHandler(f"{sys.argv[0][2:-3]}.log", mode="w")
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.DEBUG)
