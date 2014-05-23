###################################################################################################
#
# generic_epoch_timestamp.py
#   If cookie data looks like an unix timestamp, try to decode it
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

import re
import time

# Config
friendlyName = "Epoch Timestamp Decoder"
description = "Attempts to detect and decode potential epoch timestamps"
artifactTypes = ["cookie (created)", "cookie (accessed)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20120612"

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
    timestamp_re = re.compile(r'^(1(\d{9}|\d{12}))$')

    for item in items:
        if item.row_type in artifactTypes:
            if item.interpretation is None:
                m = re.search(timestamp_re, item.value)
                if m:
                    # print "Match!!"
                    # print m.group(0)
                    item.interpretation = friendly_date(int(m.group(0))) + " | [potential timestamp]"
                    # super(Chrome)
        else:
            pass
    return items
