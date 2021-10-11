###################################################################################################
#
# unfurl_interpretation.py
#   Run storage values through Unfurl to (hopefully) make some more clear.
#
# Plugin Author: Ryan Benson (ryan@dfir.blog)
#
###################################################################################################

from unfurl import core
import unfurl
import logging
# Disable most Unfurl logs, as we're about to shove a lot of garbage at it
# and don't want to swamp the Hindsight log.
try:
    unfurl.log.setLevel(logging.CRITICAL)
except Exception:
    pass

# Config
friendlyName = "Unfurl"
description = "Run storage values through Unfurl"
artifactTypes = ["local storage", "session storage"]  # Artifacts that this plugin processes
remoteLookups = 1  # if this plugin will query online sources/databases
browser = "Chrome"  # browsers that the plugin applies to
browserVersion = 1  # browser versions that the plugin applies to
version = "20210424"  # version of the plugin (use the date)
parsedItems = 0  # count of items that the plugin parsed; initialized to 0


def plugin(target_browser):

    # Setting up our return variable
    global parsedItems
    parsedItems = 0

    for item in target_browser.parsed_storage:
        # If the item isn't of a type we want to parse, go to the next one.
        if item.row_type not in artifactTypes:
            continue

        # Otherwise, try to parse the item's value with Unfurl
        try:
            u = core.Unfurl()
            u.add_to_queue(data_type='url', key=None, value=item.value)
            u.parse_queue()
            u_json = u.generate_json()

        # Many varieties of exceptions are expected here, as we're shoving
        # all kinds of data into Unfurl, many of types it isn't designed
        # to handle. That's fine; keep moving.
        except:
            continue

        # Case where Unfurl was not able to parse anything meaningful from input
        if u_json['summary'] == {}:
            continue

        # Case where the Unfurl graph is just two nodes; first is just the input again.
        # Display the second as the interpretation in a more compact form.
        if len(u_json['nodes']) == 2:
            item.interpretation = f"{u_json['nodes'][1]['label']}"

            # Try to get a description of the transform Unfurl did
            desc = u_json['nodes'][1].get('title', None)
            if not desc:
                desc = u_json['edges'][0].get('title', None)
            if desc:
                item.interpretation += f' ({desc})'

            item.interpretation += f' [Unfurl]'

        # Cases for UUIDs
        elif len(u_json['nodes']) == 3 and u_json['nodes'][2]['label'].startswith('Version 4 UUID'):
            item.interpretation = 'Value is a Version 4 UUID (randomly generated)'

        elif len(u_json['nodes']) == 3 and u_json['nodes'][2]['label'].startswith('Version 5 UUID'):
            item.interpretation = 'Value is a Version 5 UUID (generated based on a namespace and a name, ' \
                                  'which are combined and hashed using SHA-1)'

        elif len(u_json['nodes']) == 6 and u_json['nodes'][2]['label'].startswith('Version 1 UUID'):
            item.interpretation = f"{u_json['nodes'][5]['label']} (Time Generated); " \
                                  f"{u_json['nodes'][4]['label']} (MAC address); " \
                                  f"Value is a Version 1 UUID (based on time and MAC address) [Unfurl]"

        # Lastly, the generic Unfurl case. Stick the whole "ASCII-art" tree into the Interpretation field.
        else:
            item.interpretation = f"{u.generate_text_tree()} \n[Unfurl]"

        parsedItems += 1

    # Return a count parsed items
    return f'{parsedItems} values parsed'
