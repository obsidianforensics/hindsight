###################################################################################################
#
# generic_epoch_timestamp.py
#   If cookie data looks like an unix timestamp, try to decode it
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

import re

# Config
friendlyName = "Epoch Timestamp Decoder"
description = "Attempts to detect and decode potential epoch timestamps"
artifactTypes = ["cookie (created)", "cookie (accessed)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20140623"


def plugin(target_browser):
    timestamp_re = re.compile(r'^(1(\d{9}|\d{12}))$')

    for item in target_browser.parsed_artifacts:
        if item.row_type in artifactTypes:
            if item.interpretation is None:
                m = re.search(timestamp_re, item.value)
                if m:
                    # print "Match!!"
                    # print m.group(0)
                    item.interpretation = target_browser.friendly_date(int(m.group(0))) + " | [potential timestamp]"
                    # super(Chrome)
        else:
            pass
