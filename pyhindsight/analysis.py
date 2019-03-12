import sys
import os
import logging
import pytz
import time
import sqlite3
import importlib
from pyhindsight import __version__
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.brave import Brave
from pyhindsight.utils import friendly_date, format_meta_output, format_plugin_output
import pyhindsight.plugins

log = logging.getLogger(__name__)


class AnalysisSession(object):
    def __init__(self, input_path=None, profile_paths=None, cache_path=None, browser_type=None, available_input_types=None,
                 version=None, display_version=None, output_name=None, log_path=None, timezone=None,
                 available_output_formats=None, selected_output_format=None, available_decrypts=None,
                 selected_decrypts=None, parsed_artifacts=None, artifacts_display=None, artifacts_counts=None,
                 plugin_descriptions=None, selected_plugins=None, plugin_results=None, hindsight_version=None, preferences=None):
        self.input_path = input_path
        self.profile_paths = profile_paths
        self.cache_path = cache_path
        self.browser_type = browser_type
        self.available_input_types = available_input_types
        self.version = version
        self.display_version = display_version
        self.output_name = output_name
        self.log_path = log_path
        self.timezone = timezone
        self.available_output_formats = available_output_formats
        self.selected_output_format = selected_output_format
        self.available_decrypts = available_decrypts
        self.selected_decrypts = selected_decrypts
        self.parsed_artifacts = parsed_artifacts
        self.artifacts_display = artifacts_display
        self.artifacts_counts = artifacts_counts
        self.plugin_descriptions = plugin_descriptions
        self.selected_plugins = selected_plugins
        self.plugin_results = plugin_results
        self.hindsight_version = hindsight_version
        self.preferences = preferences

        if self.version is None:
            self.version = []

        if self.available_input_types is None:
            self.available_input_types = ['Chrome', 'Brave']

        if self.parsed_artifacts is None:
            self.parsed_artifacts = []

        if self.artifacts_counts is None:
            self.artifacts_counts = {}

        if self.available_output_formats is None:
            self.available_output_formats = ['sqlite']

        if self.available_decrypts is None:
            self.available_decrypts = {'windows': 0, 'mac': 0, 'linux': 0}

        if self.plugin_results is None:
            self.plugin_results = {}

        if self.preferences is None:
            self.preferences = []

        if __version__:
            self.hindsight_version = __version__

        # Try to import modules for different output formats, adding to self.available_output_format array if successful
        try:
            import xlsxwriter
            self.available_output_formats.append('xlsx')
        except ImportError:
            log.warning("Couldn't import module 'xlsxwriter'; XLSX output disabled.")

        # Set output name to default if not set by user
        if self.output_name is None:
            self.output_name = "Hindsight Report ({})".format(time.strftime('%Y-%m-%dT%H-%M-%S'))

        # Try to import modules for cookie decryption on different OSes.
        # Windows
        try:
            import win32crypt
            self.available_decrypts['windows'] = 1
        except ImportError:
            self.available_decrypts['windows'] = 0
            log.warning("Couldn't import module 'win32crypt'; cookie decryption on Windows disabled.")

        # Mac OS
        try:
            import keyring
            self.available_decrypts['mac'] = 1
        except ImportError:
            self.available_decrypts['mac'] = 0
            log.warning("Couldn't import module 'keyring'; cookie decryption on Mac OS disabled.")

        # Linux / Mac OS
        try:
            import Cryptodome.Cipher.AES
            import Cryptodome.Protocol.KDF
            self.available_decrypts['linux'] = 1
        except ImportError:
            self.available_decrypts['linux'] = 0
            self.available_decrypts['mac'] = 0
            log.warning("Couldn't import module 'Cryptodome'; cookie decryption on Linux/Mac OS disabled.")

    @staticmethod
    def sum_dict_counts(dict1, dict2):
        """Combine two dicts by summing the values of shared keys"""
        for key, value in dict2.items():
            if value == 'Failed':
                dict1[key] = dict1.setdefault(key, 0)

            elif dict1.get(key) == 'Failed':
                dict1[key] = value

            else:
                dict1[key] = dict1.setdefault(key, 0) + value
        return dict1

    def promote_object_to_analysis_session(self, item_name, item_value):
        if self.__dict__.get(item_name):
            self.__dict__[item_name]['data'].extend(item_value['data'])
            # TODO: add some checks around value of presentation. It *shouldn't* differ...
            self.__dict__[item_name]['presentation'] = item_value['presentation']

        else:
            setattr(self, item_name, item_value)

    def find_browser_profiles(self, base_path):
        """Search a path for browser profiles (only Chromium-based at the moment)."""
        found_profile_paths = []
        base_dir_listing = os.listdir(base_path)

        # The 'History' and 'Cookies' SQLite files are kind of the minimum required for most
        # Chrome analysis. This approach (checking the file names) is naive but should work.
        if {'History', 'Cookies'}.issubset(base_dir_listing):
            found_profile_paths.append(base_path)

        # Only search sub dirs if the current dir is not a Profile (Profiles are not nested).
        else:
            for item in base_dir_listing:
                item_path = os.path.join(base_path, item)
                if os.path.isdir(item_path):
                    profile_found_in_subdir = self.find_browser_profiles(item_path)
                    if profile_found_in_subdir:
                        found_profile_paths.extend(profile_found_in_subdir)

        return found_profile_paths

    def generate_display_version(self):
        self.version = sorted(self.version)
        if self.version[0] != self.version[-1]:
            self.display_version = "%s-%s" % (self.version[0], self.version[-1])
        else:
            self.display_version = self.version[0]

    def run(self):
        if self.selected_output_format is None:
            self.selected_output_format = self.available_output_formats[-1]

        if 'pytz' in sys.modules:
            # If the timezone exists, and is a string, we need to convert it to a tzinfo object
            if self.timezone is not None and isinstance(self.timezone, str):
                try:
                    self.timezone = pytz.timezone(self.timezone)
                except pytz.exceptions.UnknownTimeZoneError:
                    print("Couldn't understand timezone; using UTC.")
                    self.timezone = pytz.timezone('UTC')

            elif self.timezone is None:
                self.timezone = pytz.timezone('UTC')
        else:
            self.timezone = None

        log.debug("Options: " + str(self.__dict__))

        # Analysis start time
        log.info("Starting analysis")

        # Search input directory for browser profiles to analyze
        input_profiles = self.find_browser_profiles(self.input_path)
        log.info(" - Found {} browser profile(s): {}".format(len(input_profiles), input_profiles))
        self.profile_paths = input_profiles

        # Make sure the input is what we're expecting
        assert isinstance(self.profile_paths, list)
        assert len(self.profile_paths) >= 1

        for found_profile_path in self.profile_paths:

            if self.browser_type == "Chrome":
                browser_analysis = Chrome(found_profile_path, available_decrypts=self.available_decrypts,
                                          cache_path=self.cache_path, timezone=self.timezone)
                browser_analysis.process()
                self.parsed_artifacts.extend(browser_analysis.parsed_artifacts)
                self.artifacts_counts = self.sum_dict_counts(self.artifacts_counts, browser_analysis.artifacts_counts)
                self.artifacts_display = browser_analysis.artifacts_display
                self.version.extend(browser_analysis.version)
                self.display_version = browser_analysis.display_version
                self.preferences.extend(browser_analysis.preferences)

                for item in browser_analysis.__dict__:
                    try:
                        # If the browser_analysis attribute has 'presentation' and 'data' subkeys, promote from
                        if browser_analysis.__dict__[item]['presentation'] and browser_analysis.__dict__[item]['data']:
                            self.promote_object_to_analysis_session(item, browser_analysis.__dict__[item])
                    except:
                        log.info("Exception occurred while analyzing {} for analysis session promotion.".format(item))

            elif self.browser_type == "Brave":
                browser_analysis = Brave(found_profile_path, timezone=self.timezone)
                browser_analysis.process()
                self.parsed_artifacts = browser_analysis.parsed_artifacts
                self.artifacts_counts = browser_analysis.artifacts_counts
                self.artifacts_display = browser_analysis.artifacts_display
                self.version = browser_analysis.version
                self.display_version = browser_analysis.display_version

                for item in browser_analysis.__dict__:
                    try:
                        # If the browser_analysis attribute has 'presentation' and 'data' subkeys, promote from
                        if browser_analysis.__dict__[item]['presentation'] and browser_analysis.__dict__[item]['data']:
                            self.promote_object_to_analysis_session(item, browser_analysis.__dict__[item])
                    except:
                        pass

        self.generate_display_version()

    def run_plugins(self):
        log.info("Selected plugins: " + str(self.selected_plugins))
        completed_plugins = []

        for plugin in self.selected_plugins:

            # First check built-in plugins that ship with Hindsight
            # log.info(" Built-in Plugins:")
            for standard_plugin in pyhindsight.plugins.__all__:
                # Check if the standard plugin is the selected_plugin we're looking for
                if standard_plugin == plugin:
                    # Check to see if we've already run this plugin (likely from a different path)
                    if plugin in completed_plugins:
                        log.info(" - Skipping '{}'; a plugin with that name has run already".format(plugin))
                        continue

                    log.info(" - Loading '{}' [standard plugin]".format(plugin))
                    try:
                        module = importlib.import_module("pyhindsight.plugins.{}".format(plugin))
                    except ImportError, e:
                        log.error(" - Error: {}".format(e))
                        print format_plugin_output(plugin, "-unknown", 'import failed (see log)')
                        continue
                    try:
                        log.info(" - Running '{}' plugin".format(module.friendlyName))
                        parsed_items = module.plugin(self)
                        print format_plugin_output(module.friendlyName, module.version, parsed_items)
                        self.plugin_results[plugin] = [module.friendlyName, module.version, parsed_items]
                        log.info(" - Completed; {}".format(parsed_items))
                        completed_plugins.append(plugin)
                        break
                    except Exception, e:
                        print format_plugin_output(module.friendlyName, module.version, 'failed')
                        self.plugin_results[plugin] = [module.friendlyName, module.version, 'failed']
                        log.info(" - Failed; {}".format(e))

            for potential_path in sys.path:
                # If a subdirectory exists called 'plugins' at the current path, continue on
                potential_plugin_path = os.path.join(potential_path, 'plugins')
                if os.path.isdir(potential_plugin_path):
                    try:
                        # Insert the current plugin location to the system path, so we can import plugin modules by name
                        sys.path.insert(0, potential_plugin_path)

                        # Get list of available plugins and run them
                        plugin_listing = os.listdir(potential_plugin_path)

                        for custom_plugin in plugin_listing:
                            if custom_plugin[-3:] == ".py" and custom_plugin[0] != '_':
                                custom_plugin = custom_plugin.replace(".py", "")

                                if custom_plugin == plugin:
                                    # Check to see if we've already run this plugin (likely from a different path)
                                    if plugin in completed_plugins:
                                        log.info(" - Skipping '{}'; a plugin with that name has run already".format(plugin))
                                        continue

                                    log.debug(" - Loading '{}' [custom plugin]".format(plugin))
                                    try:
                                        module = __import__(plugin)
                                    except ImportError, e:
                                        log.error(" - Error: {}".format(e))
                                        print format_plugin_output(plugin, "-unknown", 'import failed (see log)')
                                        continue
                                    try:
                                        log.info(" - Running '{}' plugin".format(module.friendlyName))
                                        parsed_items = module.plugin(self)
                                        print format_plugin_output(module.friendlyName, module.version, parsed_items)
                                        self.plugin_results[plugin] = [module.friendlyName, module.version, parsed_items]
                                        log.info(" - Completed; {}".format(parsed_items))
                                        completed_plugins.append(plugin)
                                    except Exception, e:
                                        print format_plugin_output(module.friendlyName, module.version, 'failed')
                                        self.plugin_results[plugin] = [module.friendlyName, module.version, 'failed']
                                        log.info(" - Failed; {}".format(e))
                    except Exception as e:
                        log.debug(' - Error loading plugins ({})'.format(e))
                        print '  - Error loading plugins'
                    finally:
                        # Remove the current plugin location from the system path, so we don't loop over it again
                        sys.path.remove(potential_plugin_path)

    def generate_excel(self, output_object):
        import xlsxwriter
        workbook = xlsxwriter.Workbook(output_object, {'in_memory': True})
        w = workbook.add_worksheet(u'Timeline')

        # Define cell formats
        title_header_format = workbook.add_format({'font_color': 'white', 'bg_color': 'gray', 'bold': 'true'})
        center_header_format = workbook.add_format(
            {'font_color': 'black', 'align': 'center', 'bg_color': 'gray', 'bold': 'true'})
        header_format = workbook.add_format({'font_color': 'black', 'bg_color': 'gray', 'bold': 'true'})
        black_type_format = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_date_format = workbook.add_format({'font_color': 'black', 'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        black_url_format = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_field_format = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_value_format = workbook.add_format({'font_color': 'black', 'align': 'left', 'num_format': '0'})
        black_flag_format = workbook.add_format({'font_color': 'black', 'align': 'center'})
        black_trans_format = workbook.add_format({'font_color': 'black', 'align': 'left'})
        gray_type_format = workbook.add_format({'font_color': 'gray', 'align': 'left'})
        gray_date_format = workbook.add_format({'font_color': 'gray', 'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        gray_url_format = workbook.add_format({'font_color': 'gray', 'align': 'left'})
        gray_field_format = workbook.add_format({'font_color': 'gray', 'align': 'left'})
        gray_value_format = workbook.add_format({'font_color': 'gray', 'align': 'left', 'num_format': '0'})
        gray_wrap_format = workbook.add_format({'font_color': 'gray', 'align': 'left', 'text_wrap': True})
        red_type_format = workbook.add_format({'font_color': 'red', 'align': 'left'})
        red_date_format = workbook.add_format({'font_color': 'red', 'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        red_url_format = workbook.add_format({'font_color': 'red', 'align': 'left'})
        red_field_format = workbook.add_format({'font_color': 'red', 'align': 'right'})
        red_value_format = workbook.add_format({'font_color': 'red', 'align': 'left', 'num_format': '0'})
        green_type_format = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_date_format = workbook.add_format({'font_color': 'green', 'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        green_url_format = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_field_format = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_value_format = workbook.add_format({'font_color': 'green', 'align': 'left'})
        blue_type_format = workbook.add_format({'font_color': 'blue', 'align': 'left'})
        blue_date_format = workbook.add_format({'font_color': 'blue', 'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        blue_url_format = workbook.add_format({'font_color': 'blue', 'align': 'left'})
        blue_field_format = workbook.add_format({'font_color': 'blue', 'align': 'left'})
        blue_value_format = workbook.add_format({'font_color': 'blue', 'align': 'left'})

        # Title bar
        w.merge_range('A1:H1', u'Hindsight Internet History Forensics (v%s)' % __version__, title_header_format)
        w.merge_range('I1:M1', u'URL Specific', center_header_format)
        w.merge_range('N1:P1', u'Download Specific', center_header_format)
        w.merge_range('S1:U1', u'Cache Specific', center_header_format)

        # Write column headers
        w.write(1, 0, u'Type', header_format)
        w.write(1, 1, u'Timestamp ({})'.format(self.timezone), header_format)
        w.write(1, 2, u'URL', header_format)
        w.write(1, 3, u'Title / Name / Status', header_format)
        w.write(1, 4, u'Data / Value / Path', header_format)
        w.write(1, 5, u'Interpretation', header_format)
        w.write(1, 6, u'Profile', header_format)
        w.write(1, 7, u'Source', header_format)
        w.write(1, 8, u'Duration', header_format)
        w.write(1, 9, u'Visit Count', header_format)
        w.write(1, 10, u'Typed Count', header_format)
        w.write(1, 11, u'URL Hidden', header_format)
        w.write(1, 12, u'Transition', header_format)
        w.write(1, 13, u'Interrupt Reason', header_format)
        w.write(1, 14, u'Danger Type', header_format)
        w.write(1, 15, u'Opened?', header_format)
        w.write(1, 16, u'ETag', header_format)
        w.write(1, 17, u'Last Modified', header_format)
        w.write(1, 18, u'Server Name', header_format)
        w.write(1, 19, u'Data Location [Offset]', header_format)
        w.write(1, 20, u'All HTTP Headers', header_format)

        # Set column widths
        w.set_column('A:A', 16)  # Type
        w.set_column('B:B', 21)  # Date
        w.set_column('C:C', 60)  # URL
        w.set_column('D:D', 25)  # Title / Name / Status
        w.set_column('E:E', 80)  # Data / Value / Path
        w.set_column('F:F', 60)  # Interpretation
        w.set_column('G:G', 12)  # Profile
        w.set_column('H:H', 10)  # Source

        # URL Specific
        w.set_column('I:I', 14)  # Visit Duration
        w.set_column('J:L', 6)   # Visit Count, Typed Count, Hidden
        w.set_column('M:M', 12)  # Transition

        # Download Specific
        w.set_column('N:N', 12)  # Interrupt Reason
        w.set_column('O:O', 24)  # Danger Type
        w.set_column('P:P', 12)  # Opened

        # Common between Downloads and Cache
        w.set_column('Q:Q', 12)  # ETag
        w.set_column('R:R', 27)  # Last Modified

        # Cache Specific
        w.set_column('S:S', 18)  # Server Name
        w.set_column('T:T', 27)  # Data Location
        w.set_column('U:U', 27)  # HTTP Headers

        # Start at the row after the headers, and begin writing out the items in parsed_artifacts
        row_number = 2
        for item in self.parsed_artifacts:
            try:
                if item.row_type.startswith("url"):
                    w.write_string(row_number, 0, item.row_type, black_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), black_date_format)  # date
                    w.write_string(row_number, 2, item.url, black_url_format)  # URL
                    w.write_string(row_number, 3, item.name, black_field_format)  # Title
                    w.write(row_number, 4, "", black_value_format)  # Indexed Content
                    w.write(row_number, 5, item.interpretation, black_value_format)  # Interpretation
                    w.write(row_number, 6, item.profile, black_type_format)  # Profile
                    w.write(row_number, 7, item.visit_source, black_type_format)  # Source
                    w.write(row_number, 8, item.visit_duration, black_flag_format)  # Duration
                    w.write(row_number, 9, item.visit_count, black_flag_format)  # Visit Count
                    w.write(row_number, 10, item.typed_count, black_flag_format)  # Typed Count
                    w.write(row_number, 11, item.hidden, black_flag_format)  # Hidden
                    w.write(row_number, 12, item.transition_friendly, black_trans_format)  # Transition

                elif item.row_type.startswith("autofill"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 3, item.name, red_field_format)  # autofill field
                    w.write_string(row_number, 4, item.value, red_value_format)  # autofill value
                    w.write(row_number, 6, item.profile, red_type_format)  # Profile

                elif item.row_type.startswith("download"):
                    w.write_string(row_number, 0, item.row_type, green_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), green_date_format)  # date
                    w.write_string(row_number, 2, item.url, green_url_format)  # download URL
                    w.write_string(row_number, 3, item.status_friendly, green_field_format)  # % complete
                    w.write_string(row_number, 4, item.value, green_value_format)  # download path
                    w.write_string(row_number, 5, "", green_field_format)  # Interpretation (chain?)
                    w.write(row_number, 6, item.profile, green_type_format)  # Profile
                    w.write(row_number, 13, item.interrupt_reason_friendly, green_value_format)  # interrupt reason
                    w.write(row_number, 14, item.danger_type_friendly, green_value_format)  # danger type
                    open_friendly = ""
                    if item.opened == 1:
                        open_friendly = u'Yes'
                    elif item.opened == 0:
                        open_friendly = u'No'
                    w.write_string(row_number, 15, open_friendly, green_value_format)  # opened
                    w.write(row_number, 16, item.etag, green_value_format)  # ETag
                    w.write(row_number, 17, item.last_modified, green_value_format)  # Last Modified

                elif item.row_type.startswith("bookmark folder"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 3, item.name, red_value_format)  # bookmark name
                    w.write_string(row_number, 4, item.value, red_value_format)  # bookmark folder
                    w.write(row_number, 6, item.profile, red_value_format)  # Profile

                elif item.row_type.startswith("bookmark"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 2, item.url, red_url_format)  # URL
                    w.write_string(row_number, 3, item.name, red_value_format)  # bookmark name
                    w.write_string(row_number, 4, item.value, red_value_format)  # bookmark folder
                    w.write(row_number, 6, item.profile, red_value_format)  # Profile

                elif item.row_type.startswith("cookie"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    w.write_string(row_number, 3, item.name, gray_field_format)  # cookie name
                    w.write_string(row_number, 4, item.value, gray_value_format)  # cookie value
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # cookie interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile

                elif item.row_type.startswith("cache"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    try:
                        w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    except Exception, e:
                        print e, item.url, item.location
                    w.write_string(row_number, 3, str(item.name), gray_field_format)  # cached status // Normal (data cached)
                    w.write_string(row_number, 4, item.value, gray_value_format)  # content-type (size) // image/jpeg (2035 bytes)
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # cookie interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile
                    w.write(row_number, 16, item.etag, gray_value_format)  # ETag
                    w.write(row_number, 17, item.last_modified, gray_value_format)  # Last Modified
                    w.write(row_number, 18, item.server_name, gray_value_format)  # Server name
                    w.write(row_number, 19, item.location, gray_value_format)  # Cached data location // data_2 [1542523]
                    w.write(row_number, 20, item.http_headers_str, gray_value_format)  # Cached data location // data_2 [1542523]

                elif item.row_type.startswith("local storage"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    w.write_string(row_number, 3, item.name, gray_field_format)  # cookie name
                    w.write_string(row_number, 4, item.value, gray_value_format)  # cookie value
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # cookie interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile

                elif item.row_type.startswith("login"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 2, item.url, red_url_format)  # URL
                    w.write_string(row_number, 3, item.name, red_field_format)  # form field name
                    w.write_string(row_number, 4, item.value, red_value_format)  # username or pw value
                    w.write(row_number, 6, item.profile, red_value_format)  # Profile

                elif item.row_type.startswith("preference"):
                    w.write_string(row_number, 0, item.row_type, blue_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), blue_date_format)  # date
                    w.write_string(row_number, 2, item.url, blue_url_format)  # URL
                    w.write_string(row_number, 3, item.name, blue_field_format)  # form field name
                    w.write_string(row_number, 4, item.value, blue_value_format)  # username or pw value
                    w.write(row_number, 5, item.interpretation, blue_value_format)  # interpretation
                    w.write(row_number, 6, item.profile, blue_value_format)  # Profile

            except Exception, e:
                log.error("Failed to write row to XLSX: {}".format(e))

            row_number += 1

        # Formatting
        w.freeze_panes(2, 0)  # Freeze top row
        w.autofilter(1, 0, row_number, 19)  # Add autofilter

        for item in self.__dict__:
            try:
                if self.__dict__[item]['presentation'] and self.__dict__[item]['data']:
                    d = self.__dict__[item]
                    # TODO: try/except name exists
                    p = workbook.add_worksheet(d['presentation']['title'])
                    title = d['presentation']['title']
                    if 'version' in d['presentation']:
                        title += " (v{})".format(d['presentation']['version'])
                    p.merge_range(0, 0, 0, len(d['presentation']['columns']) - 1, "{}".format(title), title_header_format)
                    for counter, column in enumerate(d['presentation']['columns']):
                        # print column
                        p.write(1, counter, column['display_name'], header_format)
                        if 'display_width' in column:
                            p.set_column(counter, counter, column['display_width'])

                    for row_count, row in enumerate(d['data'], start=2):
                        if not isinstance(row, dict):
                            for column_count, column in enumerate(d['presentation']['columns']):
                                p.write(row_count, column_count, row.__dict__[column['data_name']], black_type_format)
                        else:
                            for column_count, column in enumerate(d['presentation']['columns']):
                                p.write(row_count, column_count, row[column['data_name']], black_type_format)

                    # Formatting
                    p.freeze_panes(2, 0)  # Freeze top row
                    p.autofilter(1, 0, len(d['data']) + 2, len(d['presentation']['columns']) - 1)  # Add autofilter

            except:
                pass

        # TODO: combine this with above function
        for item in self.__dict__.get('preferences'):
            try:
                if item['presentation'] and item['data']:
                    d = item
                    # TODO: try/except name exists
                    p = workbook.add_worksheet(d['presentation']['title'])
                    title = d['presentation']['title']
                    if 'version' in d['presentation']:
                        title += " (v{})".format(d['presentation']['version'])
                    p.merge_range(0, 0, 0, len(d['presentation']['columns']) - 1, "{}".format(title), title_header_format)
                    for counter, column in enumerate(d['presentation']['columns']):
                        # print column
                        p.write(1, counter, column['display_name'], header_format)
                        if 'display_width' in column:
                            p.set_column(counter, counter, column['display_width'])

                    for row_count, row in enumerate(d['data'], start=2):
                        if not isinstance(row, dict):
                            for column_count, column in enumerate(d['presentation']['columns']):
                                p.write(row_count, column_count, row.__dict__[column['data_name']], black_type_format)
                        else:
                            for column_count, column in enumerate(d['presentation']['columns']):
                                p.write(row_count, column_count, row[column['data_name']], black_type_format)

                    # Formatting
                    p.freeze_panes(2, 0)  # Freeze top row
                    p.autofilter(1, 0, len(d['data']) + 2, len(d['presentation']['columns']) - 1)  # Add autofilter

            except:
                pass

        workbook.close()

    def generate_sqlite(self, output_file_path='.temp_db'):

        output_db = sqlite3.connect(output_file_path)
        output_db.text_factory = lambda x: unicode(x, 'utf-8', 'ignore')

        with output_db:
            c = output_db.cursor()
            c.execute("CREATE TABLE timeline(type TEXT, timestamp TEXT, url TEXT, title TEXT, value TEXT, "
                      "interpretation TEXT, profile TEXT, source TEXT, visit_duration TEXT, visit_count INT, typed_count INT, "
                      "url_hidden INT, transition TEXT, interrupt_reason TEXT, danger_type TEXT, opened INT, etag TEXT, "
                      "last_modified TEXT, server_name TEXT, data_location TEXT, http_headers TEXT)")

            c.execute("CREATE TABLE installed_extensions(name TEXT, description TEXT, version TEXT, app_id TEXT, profile TEXT)")

            for item in self.parsed_artifacts:
                if item.row_type.startswith("url"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, interpretation, profile, source, visit_duration, visit_count, "
                              "typed_count, url_hidden, transition) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.interpretation, item.profile,
                               item.visit_source, item.visit_duration, item.visit_count, item.typed_count, item.hidden, item.transition_friendly))

                elif item.row_type.startswith("autofill"):
                    c.execute("INSERT INTO timeline (type, timestamp, title, value, interpretation, profile) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.name, item.value, item.interpretation, item.profile))

                elif item.row_type.startswith("download"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, "
                              "interrupt_reason, danger_type, opened, etag, last_modified) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.status_friendly, item.value,
                               item.interpretation, item.profile, item.interrupt_reason_friendly, item.danger_type_friendly,
                               item.opened, item.etag, item.last_modified))

                elif item.row_type.startswith("bookmark folder"):
                    c.execute("INSERT INTO timeline (type, timestamp, title, value, interpretation, profile) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.name, item.value,
                               item.interpretation, item.profile))

                elif item.row_type.startswith("bookmark"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation, item.profile))

                elif item.row_type.startswith("cookie"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation, item.profile))

                elif item.row_type.startswith("local storage"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation, item.profile))

                elif item.row_type.startswith("cache"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, "
                              "etag, last_modified, server_name, data_location)"
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, str(item.name), item.value,
                               item.interpretation, item.profile, item.etag, item.last_modified, item.server_name, item.location))

                elif item.row_type.startswith("login"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation, item.profile))

                elif item.row_type.startswith("preference"):
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation, item.profile))

            if self.__dict__.get("installed_extensions"):
                for extension in self.installed_extensions['data']:
                    c.execute("INSERT INTO installed_extensions (name, description, version, app_id, profile) "
                              "VALUES (?, ?, ?, ?, ?)",
                              (extension.name, extension.description, extension.version, extension.app_id, extension.profile))


