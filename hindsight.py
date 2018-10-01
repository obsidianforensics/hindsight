#!/usr/bin/env python

"""Hindsight - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome data folder, runs various plugins
against the data, and then outputs the results in a spreadsheet.
"""

import os
import sys
import time
import datetime
import argparse
import logging
import json
import shutil
import importlib
import pyhindsight
import pyhindsight.plugins
from pyhindsight.analysis import AnalysisSession
from pyhindsight.utils import banner, MyEncoder, format_meta_output, format_plugin_output

# Try to import module for timezone support
try:
    import pytz
except ImportError:
    print("Couldn't import module 'pytz'; all timestamps in XLSX output will be in examiner local time ({})."
          .format(time.tzname[time.daylight]))


def parse_arguments(analysis_session):
    description = '''
Hindsight v{} - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome/Chromium/Brave data folder, runs various plugins
   against the data, and then outputs the results in a spreadsheet. '''.format(pyhindsight.__version__)

    epi = '''
Example:  C:\>hindsight.py -i "C:\Users\Ryan\AppData\Local\Google\Chrome\User Data\Default" -o test_case

The Chrome data folder default locations are:
        WinXP: <userdir>\Local Settings\Application Data\Google\Chrome
                \User Data\Default\\
    Vista/7/8: <userdir>\AppData\Local\Google\Chrome\User Data\Default\\
        Linux: <userdir>/.config/google-chrome/Default/
         OS X: <userdir>/Library/Application Support/Google/Chrome/Default/
          iOS: \Applications\com.google.chrome.ios\Library\Application Support
                \Google\Chrome\Default\\
    '''

    class MyParser(argparse.ArgumentParser):
        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)

    parser = MyParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description,
        epilog=epi)

    parser.add_argument('-i', '--input', help='Path to the Chrome(ium) "Default" directory', required=True)
    parser.add_argument('-o', '--output', help='Name of the output file (without extension)')
    parser.add_argument('-b', '--browser_type', help='Type of input files', default='Chrome',
                        choices=['Chrome', 'Brave'])
    parser.add_argument('-f', '--format', choices=analysis_session.available_output_formats,
                        default=analysis_session.available_output_formats[-1], help='Output format')
    parser.add_argument('-l', '--log', help='Location Hindsight should log to (will append if exists)',
                        default='hindsight.log')
    parser.add_argument('-t', '--timezone', help='Display timezone for the timestamps in XLSX output', default='UTC')
    parser.add_argument('-d', '--decrypt', choices=['mac', 'linux'], default=None,
                        help='Try to decrypt Chrome data from a Linux or Mac system; support for both is currently '
                             'buggy and enabling this may cause problems. Only use "--decrypt linux" on data from a '
                             'Linux system, and only use "--decrypt mac" when running Hindsight on the same Mac the '
                             'Chrome data is from.')
    parser.add_argument('-c', '--cache', help='Path to the cache directory; only needed if the directory is outside '
                                              'the given "input" directory. Mac systems are setup this way by default.')

    args = parser.parse_args()

    if args.timezone:
        try:
            __import__('pytz')
        except ImportError:
            args.timezone = None
        else:
            try:
                args.timezone = pytz.timezone(args.timezone)
            except pytz.exceptions.UnknownTimeZoneError:
                print("Couldn't understand timezone; using UTC.")
                args.timezone = pytz.timezone('UTC')

    # Disable decryption on Linux unless explicitly enabled and supported
    if args.decrypt == 'linux' and analysis_session.available_decrypts['linux'] == 1:
        analysis_session.available_decrypts['linux'] = 1
    else:
        analysis_session.available_decrypts['linux'] = 0

    # Disable decryption on Mac unless explicitly enabled and supported
    if args.decrypt == 'mac' and analysis_session.available_decrypts['mac'] == 1:
        analysis_session.available_decrypts['mac'] = 1
    else:
        analysis_session.available_decrypts['mac'] = 0

    return args


def main():

    def write_excel(analysis_session):
        import StringIO

        # Set up a StringIO object to save the XLSX content to before saving to disk
        string_buffer = StringIO.StringIO()

        # Generate the XLSX content using the function in the AnalysisSession and save it to the StringIO object
        analysis_session.generate_excel(string_buffer)

        # Go back to the beginning (be kind, rewind)
        string_buffer.seek(0)

        # Write the StringIO object to a file on disk named what the user specified
        with open("{}.{}".format(os.path.join(real_path, analysis_session.output_name), analysis_session.selected_output_format), 'wb') as file_output:
            shutil.copyfileobj(string_buffer, file_output)

    def write_sqlite(analysis_session):
        output_file = analysis_session.output_name + '.sqlite'

        if not os.path.exists(output_file):
            analysis_session.generate_sqlite(output_file)
        else:
            print("\n Database file \"{}\" already exists. Please choose a different output location.\n".format(output_file))

    print(banner)

    # Useful when Hindsight is run from a different directory than where the file is located
    real_path = os.path.dirname(os.path.realpath(sys.argv[0]))

    # Set up the AnalysisSession object, and transfer the relevant input arguments to it
    analysis_session = AnalysisSession()
    args = parse_arguments(analysis_session)
    analysis_session.profile_path = args.input
    if args.output:
        analysis_session.output_name = args.output

    if args.cache:
        analysis_session.cache_path = args.cache

    analysis_session.selected_output_format = args.format
    analysis_session.browser_type = args.browser_type
    analysis_session.timezone = args.timezone

    if args.log == 'hindsight.log':
        args.log = os.path.join(real_path, args.log)
    analysis_session.log_path = args.log

    # Set up logging
    logging.basicConfig(filename=analysis_session.log_path, level=logging.DEBUG,
                        format='%(asctime)s.%(msecs).03d | %(levelname).01s | %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(__name__)

    # Hindsight version info
    log.info(
        '\n' + '#' * 80 + '\n###    Hindsight v{} (https://github.com/obsidianforensics/hindsight)    ###\n'
        .format(pyhindsight.__version__) + '#' * 80)

    # Analysis start time
    print(format_meta_output("Start time", str(datetime.datetime.now())[:-3]))

    # Read the input directory
    print(format_meta_output("Input directory", args.input))
    log.info("Reading files from %s" % args.input)
    input_listing = os.listdir(args.input)
    log.debug("Input directory contents: " + str(input_listing))
    print(format_meta_output("Output name", "{}.{}".format(analysis_session.output_name, analysis_session.selected_output_format)))

    # Run the AnalysisSession
    print("\n Processing:")
    analysis_session.run()

    print("\n Running plugins:")
    log.info("Plugins:")
    completed_plugins = []

    # First run built-in plugins that ship with Hindsight
    log.info(" Built-in Plugins:")
    for plugin in pyhindsight.plugins.__all__:
        # Check to see if we've already run this plugin (likely from a different path)
        if plugin in completed_plugins:
            continue

        log.debug(" - Loading '{}'".format(plugin))
        try:
            module = importlib.import_module("pyhindsight.plugins.{}".format(plugin))
        except ImportError, e:
            log.error(" - Error: {}".format(e))
            print(format_plugin_output(plugin, "-unknown", 'import failed (see log)'))
            continue
        try:
            log.info(" - Running '{}' plugin".format(module.friendlyName))
            parsed_items = module.plugin(analysis_session)
            print(format_plugin_output(module.friendlyName, module.version, parsed_items))
            log.info(" - Completed; {}".format(parsed_items))
            completed_plugins.append(plugin)
        except Exception, e:
            print(format_plugin_output(module.friendlyName, module.version, 'failed'))
            log.info(" - Failed; {}".format(e))

    # Then look for any custom user-provided plugins in a 'plugins' directory
    log.info(" Custom Plugins:")

    if real_path not in sys.path:
        sys.path.insert(0, real_path)

    # Loop through all paths, to pick up all potential locations for custom plugins
    for potential_path in sys.path:
        # If a subdirectory exists called 'plugins' or 'pyhindsight/plugins' at the current path, continue on
        for potential_plugin_path in [os.path.join(potential_path, 'plugins'), os.path.join(potential_path, 'pyhindsight', 'plugins')]:
            if os.path.isdir(potential_plugin_path):
                log.info(" Found custom plugin directory {}:".format(potential_plugin_path))
                try:
                    # Insert the current plugin location to the system path, so we can import plugin modules by name
                    sys.path.insert(0, potential_plugin_path)

                    # Get list of available plugins and run them
                    plugin_listing = os.listdir(potential_plugin_path)

                    log.debug(" - Contents of plugin folder: " + str(plugin_listing))
                    for plugin in plugin_listing:
                        if plugin[-3:] == ".py" and plugin[0] != '_':
                            plugin = plugin.replace(".py", "")

                            # Check to see if we've already run this plugin (likely from a different path)
                            if plugin in completed_plugins:
                                log.debug(" - Skipping '{}'; a plugin with that name has run already".format(plugin))
                                continue

                            log.debug(" - Loading '{}'".format(plugin))
                            try:
                                module = __import__(plugin)
                            except ImportError, e:
                                log.error(" - Error: {}".format(e))
                                print(format_plugin_output(plugin, "-unknown", 'import failed (see log)'))
                                continue
                            try:
                                log.info(" - Running '{}' plugin".format(module.friendlyName))
                                parsed_items = module.plugin(analysis_session)
                                print(format_plugin_output(module.friendlyName, module.version, parsed_items))
                                log.info(" - Completed; {}".format(parsed_items))
                                completed_plugins.append(plugin)
                            except Exception, e:
                                print(format_plugin_output(module.friendlyName, module.version, 'failed'))
                                log.info(" - Failed; {}".format(e))
                except Exception as e:
                    log.debug(' - Error loading plugins ({})'.format(e))
                    print('  - Error loading plugins')
                finally:
                    # Remove the current plugin location from the system path, so we don't loop over it again
                    sys.path.remove(potential_plugin_path)

    # Check if output directory exists; attempt to create if it doesn't
    if os.path.dirname(analysis_session.output_name) != "" and not os.path.exists(os.path.dirname(analysis_session.output_name)):
        os.makedirs(os.path.dirname(analysis_session.output_name))

    # Get desired output type form args.format and call the correct output creation function
    if analysis_session.selected_output_format == 'xlsx':
        log.info("Writing output; XLSX format selected")
        try:
            print("\n Writing {}.xlsx".format(analysis_session.output_name))
            write_excel(analysis_session)
        except IOError:
            type, value, traceback = sys.exc_info()
            print(value, "- is the file open?  If so, please close it and try again.")
            log.error("Error writing XLSX file; type: {}, value: {}, traceback: {}".format(type, value, traceback))

    elif args.format == 'json':
        log.info("Writing output; JSON format selected")
        output = open("{}.json".format(analysis_session.output_name), 'wb')
        output.write(json.dumps(analysis_session, cls=MyEncoder, indent=4))

    elif args.format == 'sqlite':
        log.info("Writing output; SQLite format selected")
        print("\n Writing {}.sqlite".format(analysis_session.output_name))
        write_sqlite(analysis_session)

    # Display and log finish time
    print("\n Finish time: {}".format(str(datetime.datetime.now())[:-3]))
    log.info("Finish time: {}\n\n".format(str(datetime.datetime.now())[:-3]))


if __name__ == "__main__":
    main()
