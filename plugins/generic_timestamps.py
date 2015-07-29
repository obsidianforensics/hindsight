###################################################################################################
#
# generic_timestamps.py
#   If cookie data looks like it might be a timestamp, try to decode it
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

import re

# Config
friendlyName = "Generic Timestamp Decoder"
description = "Attempts to detect and decode potential epoch second, epoch millisecond, and Webkit timestamps"
artifactTypes = ("cookie (created)", "cookie (accessed)", "local storage")
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20140816"
parsedItems = 0


def plugin(target_browser):
    timestamp_re = re.compile(r'^(1(\d{9}|\d{12}|\d{16}))$')
    ls_timestamp_re = re.compile(r'timestamp.*?(\d{10,17})')
    global parsedItems

    for item in target_browser.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            if item.interpretation is None:
                m = re.search(timestamp_re, item.value)
                ls_m = re.search(ls_timestamp_re, item.value)
                if m:
                    item.interpretation = target_browser.friendly_date(int(m.group(0))) + u' [potential timestamp]'
                    parsedItems += 1
                elif ls_m:
                    item.interpretation = target_browser.friendly_date(int(ls_m.group(1))) + u' [potential timestamp]'
                    parsedItems += 1

    # Description of what the plugin did
    return u"{} timestamps parsed".format(parsedItems)