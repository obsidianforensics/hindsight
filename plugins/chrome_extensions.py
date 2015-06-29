###################################################################################################
#
# chrome_extensions.py
#   Adds the name and description of each Chrome extension found in a URLItem to the Interpretation field
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

import re

# Config
friendlyName = "Chrome Extension Names"
description = "Adds the name and description of each Chrome extension found in a URLItem to the Interpretation field"
artifactTypes = ["url", "url (archived)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20150125"
parsedItems = 0


def plugin(target_browser):
    extension_re = re.compile(r'^chrome-extension://([a-z]{32})')
    global parsedItems

    for item in target_browser.parsed_artifacts:
        if item.row_type in artifactTypes:
            if item.interpretation is None:
                m = re.search(extension_re, item.url)
                if m:
                    try:
                        for ext in target_browser.installed_extensions['data']:
                            if ext.app_id == m.group(1):
                                item.interpretation = u'{} ({}) [Chrome Extension]'.format(ext.name, ext.description)
                                parsedItems += 1
                    except:
                        pass

    # Description of what the plugin did
    return u'{} extension URLs parsed'.format(parsedItems)
