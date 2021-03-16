###################################################################################################
#
# unfurl_interpretation.py
#   Run storage values through Unfurl to (hopefully) make some more clear.
#
# Plugin Author: Ryan Benson (ryan@dfir.blog)
#
###################################################################################################

import json
import datetime
import pytz
import re

# Config
friendlyName = "Media Router"
description = "Run storage values through Unfurl"
artifactTypes = ["local storage"]  # Artifacts that this plugin processes
remoteLookups = 1  # if this plugin will query online sources/databases
browser = "Chrome"  # browsers that the plugin applies to
browserVersion = 1  # browser versions that the plugin applies to
version = "20210307"  # version of the plugin (use the date)
parsedItems = 0  # count of items that the plugin parsed; initialized to 0


def plugin(target_browser):

    # Setting up our return variable
    global parsedItems
    parsedItems = 0

    mr_rows = []

    for item in target_browser.parsed_storage:
        # If the item isn't of a type we want to parse, go to the next one.
        if item.row_type not in artifactTypes:
            continue

        # If the item already has an interpretation don't replace it.
        if item.origin != 'chrome-extension://pkedcjkdefgpdelpbcmbmeomcjbeemfm':
            continue

        if item.key == 'mr.temp.LogManager':
            mr_logs = json.loads(item.value)
            mr_log_re = re.compile(
                r'\[(?P<timestamp>.*?)\]\[(?P<log_level>.*?)\]\[(?P<mr_component>.*?)\] (?P<message>.*)')

            for mr_log in mr_logs:
                log_extract = mr_log_re.match(mr_log)
                mr_log_ts = datetime.datetime.strptime(log_extract.group('timestamp'), '%Y-%m-%d %H:%M:%S.%f',)
                mr_log_ts = mr_log_ts.replace(tzinfo=pytz.UTC)

                from pyhindsight.browsers.webbrowser import WebBrowser
                mr_row = WebBrowser.PreferenceItem(
                    profile=item.profile,
                    url=f'{item.origin} (Chrome Media Router)',
                    timestamp=mr_log_ts,
                    key=log_extract.group('mr_component'),
                    value=log_extract.group('message'),
                    interpretation=None
                )
                mr_rows.append(mr_row)

    target_browser.parsed_artifacts.extend(mr_rows)
    parsedItems = len(mr_rows)

    # Return a count parsed items
    return f'{parsedItems} logs parsed'
