###################################################################################################
#
# query_string_parser.py
#   Extracts the query string from a URL and prints each parameter and value.
#
# Plugin Author: Your Name Here (ryan@obsidianforensics.com)
#
###################################################################################################

import urlparse

# Config
friendlyName = "Query String Parser"
description = "Extracts the query string from a URL and prints each field and value."
artifactTypes = ["url", "url (archived)"]  # Artifacts that this plugin processes
remoteLookups = 0  # if this plugin will query online sources/databases
browser = "all"  # browsers that the plugin applies to
version = "20150222"  # version of the plugin (use the date)
parsedItems = 0  # count of items that the plugin parsed; initialized to 0


def plugin(target_browser):

    # Setting up our return variable
    global parsedItems

    for item in target_browser.parsed_artifacts:                # For each item that Hindsight has parsed,
        if item.row_type in artifactTypes:                      # if the row if of a supported type for this plugin, and
            if item.interpretation is None:                     # if there isn't already an interpretation,
                parsed_url = urlparse.urlparse(item.url)
                query_string_dict = urlparse.parse_qs(parsed_url.query)

                if len(query_string_dict) > 0:                  # Check if we have any field/value pairs.
                    query_string = ''                           # Create our return string; start it off empty.
                    for field, value in query_string_dict.items():  # Add each field/value to the return string
                        query_string += "{}: {} | ".format(field.encode('ascii', 'xmlcharrefreplace'),
                                                           value[0].encode('ascii', 'xmlcharrefreplace'))

                                                                # Set the interpretation to the string
                    item.interpretation = query_string[:-2] + " [Query String Parser]"
                    parsedItems += 1                            # Increment the count of parsed items

    # Lastly, a count of parsed items with a description of what the plugin did
    return "%s query strings parsed" % parsedItems