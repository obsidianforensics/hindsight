###################################################################################################
#
# quantcast_cookies.py
#   Interpret Quantcast cookies* (parsing partially complete)
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

import re

# Config
friendlyName = "Quantcast Cookie Parser"
description = "Parses Quantcast cookies"
artifactTypes = ["cookie (created)", "cookie (accessed)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20140623"


def plugin(target_browser):
    timestamp_re = re.compile(r'^(P0)-(\d+)-(\d{10,13})$')

    for item in target_browser.parsed_artifacts:
        if item.row_type in artifactTypes:
            if item.name == '__qca':
                m = re.search(timestamp_re, item.value)
                if m:
                    item.interpretation = target_browser.friendly_date(int(m.group(3))) + " | [Quantcast Cookie Timestamp]"
