###################################################################################################
#
# chrome_extensions.py
#   Adds the name and description of each Chrome extension found in a URLItem to the Interpretation field
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

# Config
friendlyName = "Chrome Extension Names"
description = "Adds the name and description of each Chrome extension found in a URLItem to the Interpretation field"
artifactTypes = ("url", "local storage")
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20150125"
parsedItems = 0


def plugin(analysis_session=None):
    import re
    if analysis_session is None:
        return

    extension_re = re.compile(r'^chrome-extension[_|://]([a-z]{32})')
    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            if item.interpretation is None:
                m = re.search(extension_re, item.url)
                if m:
                    try:
                        for ext in analysis_session.installed_extensions['data']:
                            if ext.app_id == m.group(1):
                                item.interpretation = '{} ({}) [Chrome Extension]'.format(ext.name, ext.description)
                                parsedItems += 1
                    except:
                        pass

    # Description of what the plugin did
    return '{} extension URLs parsed'.format(parsedItems)
