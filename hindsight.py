#!/usr/bin/env python3

"""Hindsight - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome data folder, runs various plugins
against the data, and then outputs the results in a spreadsheet.
"""

import argparse
import datetime
import importlib
import logging
import os
import re
import shutil
import sys
import time

import pyhindsight
import pyhindsight.plugins
from pyhindsight.analysis import AnalysisSession
from pyhindsight.utils import banner, format_meta_output, format_plugin_output

# Try to import module for timezone support
try:
    import pytz
except ImportError:
    print(f'Could not import module \'pytz\'; all timestamps in XLSX output '
          f'will be in examiner local time ({time.tzname[time.daylight]}).')


def parse_arguments(analysis_session):
    description = f'''
Hindsight v{pyhindsight.__version__} - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome/Chromium/Brave data folder, runs various plugins
   against the data, and then outputs the results in a spreadsheet. '''

    epi = r'''
Example:  C:\hindsight.py -i "C:\Users\Ryan\AppData\Local\Google\Chrome\User Data\Default" -o test_case

The Chrome data folder default locations are:
        WinXP: <userdir>\Local Settings\Application Data\Google\Chrome
                \User Data\Default\
 Vista/7/8/10: <userdir>\AppData\Local\Google\Chrome\\User Data\Default\
        Linux: <userdir>/.config/google-chrome/Default/
         OS X: <userdir>/Library/Application Support/Google/Chrome/Default/
          iOS: \Applications\com.google.chrome.ios\Library\Application Support
                \Google\Chrome\Default\
  Chromium OS: \home\user\<GUID>\
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

    parser.add_argument('-i', '--input', required=True,
                        help='Path to the Chrome(ium) profile directory (typically "Default"). If a higher-level '
                             'directory is specified instead, Hindsight will recursively search for profiles.', )
    parser.add_argument('-o', '--output', help='Name of the output file (without extension)')
    parser.add_argument('-b', '--browser_type', help='Type of input files', default='Chrome',
                        choices=['Chrome', 'Brave'])
    parser.add_argument('-f', '--format', choices=analysis_session.available_output_formats,
                        default=analysis_session.available_output_formats[-1], help='Output format')
    parser.add_argument('-l', '--log', help='Location Hindsight should log to (will append if exists)',
                        default=os.path.join(os.getcwd(), 'hindsight.log'))
    parser.add_argument('-t', '--timezone', help='Display timezone for the timestamps in XLSX output', default='UTC')
    parser.add_argument('-d', '--decrypt', choices=['mac', 'linux'], default=None,
                        help='Try to decrypt Chrome data from a Linux or Mac system; support for both is currently '
                             'buggy and enabling this may cause problems. Only use "--decrypt linux" on data from a '
                             'Linux system, and only use "--decrypt mac" when running Hindsight on the same Mac the '
                             'Chrome data is from.')
    parser.add_argument('-c', '--cache',
                        help='Path to the cache directory; only needed if the directory is outside the given "input" '
                             'directory. Mac systems are set up this way by default. On a Mac, the default cache '
                             'directory location for Chrome is <userdir>/Library/Caches/Google/Chrome/Default/Cache/')
    parser.add_argument('--nocopy', '--no_copy', help='Don\'t copy files before opening them; this might run faster, '
                                                      'but some locked files may be inaccessible', action='store_true')
    parser.add_argument('--temp_dir', default='hindsight-temp',
                        help='If files are copied before being opened, use this directory as the copy destination')

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
        import io

        # Set up a StringIO object to save the XLSX content to before saving to disk
        string_buffer = io.BytesIO()

        # Generate the XLSX content using the function in the AnalysisSession and save it to the StringIO object
        analysis_session.generate_excel(string_buffer)

        # Go back to the beginning (be kind, rewind)
        string_buffer.seek(0)

        # Write the StringIO object to a file on disk named what the user specified
        with open(f'{analysis_session.output_name}.{analysis_session.selected_output_format}', 'wb') as file_output:
            shutil.copyfileobj(string_buffer, file_output)

    def write_sqlite(analysis_session):
        output_file = analysis_session.output_name + '.sqlite'

        if os.path.exists(output_file):
            if os.path.getsize(output_file) > 0:
                print(('\nDatabase file "{}" already exists.\n'.format(output_file)))
                user_input = input('Would you like to (O)verwrite it, (R)ename output file, or (E)xit? ')
                over_re = re.compile(r'(^o$|overwrite)', re.IGNORECASE)
                rename_re = re.compile(r'(^r$|rename)', re.IGNORECASE)
                exit_re = re.compile(r'(^e$|exit)', re.IGNORECASE)
                if re.search(exit_re, user_input):
                    print("Exiting... ")
                    sys.exit()
                elif re.search(over_re, user_input):
                    os.remove(output_file)
                    print(("Deleted old \"%s\"" % output_file))
                elif re.search(rename_re, user_input):
                    output_file = "{}_1.sqlite".format(output_file[:-7])
                    print(("Renaming new output to {}".format(output_file)))
                else:
                    print("Did not understand response.  Exiting... ")
                    sys.exit()

        analysis_session.generate_sqlite(output_file)

    def write_jsonl(analysis_session):
        output_file = analysis_session.output_name + '.jsonl'
        analysis_session.generate_jsonl(output_file)

    print(banner)

    # Useful when Hindsight is run from a different directory than where the file is located
    real_path = os.path.dirname(os.path.realpath(sys.argv[0]))

    # Set up the AnalysisSession object, and transfer the relevant input arguments to it
    analysis_session = AnalysisSession()

    # parse_arguments needs the analysis_session as an input to set things like available decrypts
    args = parse_arguments(analysis_session)

    if args.output:
        analysis_session.output_name = args.output

    if args.cache:
        analysis_session.cache_path = args.cache

    analysis_session.selected_output_format = args.format
    analysis_session.browser_type = args.browser_type
    analysis_session.timezone = args.timezone
    analysis_session.no_copy = args.nocopy
    analysis_session.temp_dir = args.temp_dir
    analysis_session.log_path = args.log

    # Set up logging
    logging.basicConfig(filename=analysis_session.log_path, level=logging.DEBUG,
                        format='%(asctime)s.%(msecs).03d | %(levelname).01s | %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(__name__)

    # Hindsight version info
    log.info(
        '\n' + '#' * 80 +
        f'\n##   Hindsight v{pyhindsight.__version__} (https://github.com/obsidianforensics/hindsight)   ##\n' +
        '#' * 80)

    # Analysis start time
    print((format_meta_output("Start time", str(datetime.datetime.now())[:-3])))

    # Print input & output directories
    analysis_session.input_path = args.input
    print((format_meta_output('Input directory', args.input)))
    print((format_meta_output(
        'Output name', f'{analysis_session.output_name}.{analysis_session.selected_output_format}')))

    # Run the AnalysisSession
    print("\n Processing:")
    run_status = analysis_session.run()
    if not run_status:
        if analysis_session.fatal_error:
            print(f"\n Fatal Error '{analysis_session.fatal_error}'")
        sys.exit(1)

    print("\n Running plugins:")
    log.info("Plugins:")
    completed_plugins = []

    # First run built-in plugins that ship with Hindsight
    log.info(" Built-in Plugins:")
    for plugin in pyhindsight.plugins.__all__:
        # Check to see if we've already run this plugin (likely from a different path)
        if plugin in completed_plugins:
            continue

        log.debug(f" - Loading '{plugin}'")
        try:
            module = importlib.import_module(f'pyhindsight.plugins.{plugin}')
        except ImportError as e:
            log.error(f' - Error: {e}')
            print((format_plugin_output(plugin, "-unknown", 'import failed (see log)')))
            continue
        except Exception as e:
            log.error(f' - Exception in {plugin} plugin: {e}')
            continue

        try:
            log.info(f" - Running '{module.friendlyName}' plugin")
            parsed_items = module.plugin(analysis_session)
            print((format_plugin_output(module.friendlyName, module.version, parsed_items)))
            log.info(f' - Completed; {parsed_items}')
            completed_plugins.append(plugin)
        except Exception as e:
            print((format_plugin_output(module.friendlyName, module.version, 'failed')))
            log.info(f' - Failed; {e}')

    # Then look for any custom user-provided plugins in a 'plugins' directory
    log.info(" Custom Plugins:")

    if real_path not in sys.path:
        sys.path.insert(0, real_path)

    # Loop through all paths, to pick up all potential locations for custom plugins
    for potential_path in sys.path:
        # If a subdirectory exists called 'plugins' or 'pyhindsight/plugins' at the current path, continue on
        for potential_plugin_path in [os.path.join(potential_path, 'plugins'),
                                      os.path.join(potential_path, 'pyhindsight', 'plugins')]:
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
                            except ImportError as e:
                                log.error(f' - Error: {e}')
                                print((format_plugin_output(plugin, "-unknown", 'import failed (see log)')))
                                continue
                            except Exception as e:
                                log.error(f' - Exception in {plugin} plugin: {e}')

                            try:
                                log.info(" - Running '{}' plugin".format(module.friendlyName))
                                parsed_items = module.plugin(analysis_session)
                                print((format_plugin_output(module.friendlyName, module.version, parsed_items)))
                                log.info(" - Completed; {}".format(parsed_items))
                                completed_plugins.append(plugin)
                            except Exception as e:
                                print((format_plugin_output(module.friendlyName, module.version, 'failed')))
                                log.info(" - Failed; {}".format(e))
                except Exception as e:
                    log.debug(' - Error loading plugins ({})'.format(e))
                    print('  - Error loading plugins')
                finally:
                    # Remove the current plugin location from the system path, so we don't loop over it again
                    sys.path.remove(potential_plugin_path)

    # Check if output directory exists; attempt to create if it doesn't
    if os.path.dirname(analysis_session.output_name) != "" \
            and not os.path.exists(os.path.dirname(analysis_session.output_name)):
        os.makedirs(os.path.dirname(analysis_session.output_name))

    # Get desired output type form args.format and call the correct output creation function
    if analysis_session.selected_output_format == 'xlsx':
        log.info("Writing output; XLSX format selected")
        try:
            print(("\n Writing {}.xlsx".format(analysis_session.output_name)))
            write_excel(analysis_session)
        except IOError:
            error_type, value, traceback = sys.exc_info()
            print((value, "- is the file open?  If so, please close it and try again."))
            log.error(f"Error writing XLSX file; type: {error_type}, value: {value}, traceback: {traceback}")

    elif args.format == 'jsonl':
        log.info("Writing output; JSONL format selected")
        print(("\n Writing {}.jsonl".format(analysis_session.output_name)))
        write_jsonl(analysis_session)

    elif args.format == 'sqlite':
        log.info("Writing output; SQLite format selected")
        print(("\n Writing {}.sqlite".format(analysis_session.output_name)))
        write_sqlite(analysis_session)

    # Display and log finish time
    print(f'\n Finish time: {str(datetime.datetime.now())[:-3]}')
    log.info(f'Finish time: {str(datetime.datetime.now())[:-3]}\n\n')


if __name__ == "__main__":
    main()
