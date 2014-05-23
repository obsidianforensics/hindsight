###################################################################################################
#
# quantcast_cookies.py
#   Interpret Quantcast cookies* (parsing partially complete)
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

import re
import time

# Config
friendlyName = "Quantcast Cookie Parser"
description = "Parses Quantcast cookies"
artifactTypes = ["cookie (created)", "cookie (accessed)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20120611"


def friendly_date(timestamp):
    if timestamp > 99999999999999:
        # Webkit
        print(timestamp)
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime((int(timestamp)/1000000)-11644473600))
    elif timestamp > 99999999999:
        # Epoch milliseconds
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(timestamp/1000))
    elif timestamp > 1:
        # Epoch
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(timestamp))
    else:
        return "error"


def plugin(items):
    timestamp_re = re.compile(r'^(P0)-(\d+)-(\d{10,13})$')

    for item in items:
        if item.row_type in artifactTypes:
            if item.name == '__qca':
                m = re.search(timestamp_re, item.value)
                if m:
                    item.interpretation = friendly_date(int(m.group(3))) + " | [Quantcast Cookie Timestamp]"
    return items
