###################################################################################################
#
# quantcast_cookies.py
#   Interpret Quantcast cookies* (parsing partially complete)
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

import hindsight
import re

# Config
friendlyName = "Quantcast Cookie Parser"
description = "Parses Quantcast cookies"
artifactTypes = ["cookie (created)", "cookie (accessed)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20160907"
parsedItems = 0


def plugin(target_browser):
    timestamp_re = re.compile(r'^(P0)-(\d+)-(\d{10,13})$')
    global parsedItems

    for item in target_browser.parsed_artifacts:
        if item.row_type in artifactTypes:
            if item.name == u'__qca':
                m = re.search(timestamp_re, item.value)
                if m:
                    item.interpretation = hindsight.friendly_date(int(m.group(3))) \
                                          + u' [Quantcast Cookie Timestamp]'
                    parsedItems += 1

    # Description of what the plugin did
    return u"{} cookies parsed".format(parsedItems)
