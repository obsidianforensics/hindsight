import datetime
import importlib
import json
import logging
import os
import sqlite3
import sys
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pyhindsight import __version__
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.brave import Brave
from pyhindsight.browsers.webbrowser import WebBrowser
from pyhindsight.utils import friendly_date
import pyhindsight.plugins
import rich.align
import rich.console
import rich.live
import rich.spinner
import rich.table
import rich.text

log = logging.getLogger(__name__)


class HindsightEncoder(json.JSONEncoder):
    """This JSONEncoder translates several Hindsight HistoryItem classes into
    JSON objects for use in the JSONL output format. It also makes changes
    to field names and values to more closely align with Plaso
    (https://github.com/log2timeline/plaso) output for easier use with
    Timesketch (https://github.com/google/timesketch/).
    """

    @staticmethod
    def base_encoder(history_item):
        item = {'source_short': 'WEBHIST', 'source_long': 'Chrome History',
                'parser': f'hindsight/{__version__}'}
        for key, value in list(history_item.__dict__.items()):
            # Drop any keys that have None as value
            if value is None:
                continue

            if key == 'interpretation' and value == '':
                continue

            if isinstance(value, datetime.datetime):
                value = value.isoformat()

            # JSONL requires utf-8 encoding
            if isinstance(value, bytes) or isinstance(value, bytearray):
                value = value.decode('utf-8', errors='replace')

            if isinstance(key, bytes) or isinstance(key, bytearray):
                key = key.decode('utf-8', errors='replace')

            item[key] = value

        if item.get('timestamp'):
            item['datetime'] = item['timestamp']
            del(item['timestamp'])
        else:
            item['datetime'] = '1970-01-01T00:00:00.000000+00:00'

        return item

    def default(self, obj):
        if isinstance(obj, Chrome.URLItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Last Visited Time'
            item['data_type'] = 'chrome:history:page_visited'
            item['url_hidden'] = 'true' if item['hidden'] else 'false'
            if item['visit_duration'] == 'None':
                del (item['visit_duration'])

            item['message'] = f"{item['url']} ({item['title']}) [count: {item['visit_count']}]"

            del(item['name'], item['row_type'], item['visit_time'],
                item['last_visit_time'], item['hidden'])
            return item

        if isinstance(obj, Chrome.MediaItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Media Playback End'
            item['data_type'] = 'chrome:history:media_playback'

            if item.get('source_title'):
                item['message'] = f"Watched{item['watch_time']} on {item['source_title']} "\
                                  f"(ending at {item['position']}/{item.get('media_duration')}) " \
                                  f"[has_video: {item['has_video']}; has_audio: {item['has_audio']}]"
            else:
                item['message'] = f"Watched{item['watch_time']} on {item['url']} " \
                                  f"[has_video: {item['has_video']}; has_audio: {item['has_audio']}]"

            return item

        if isinstance(obj, Chrome.SessionItem):
            item = HindsightEncoder.base_encoder(obj)
            item['source_long'] = 'Chrome Sessions'

            row_type = item.get('row_type', '')
            if 'closed' in row_type and 'navigation' not in row_type:
                item['timestamp_desc'] = 'Close Time'
                item['data_type'] = f'chrome:session:{row_type.split("(")[1].rstrip(")").replace(" ", "_")}'
                item['message'] = f'{row_type}: {item.get("value", "")}'
            elif 'last active' in row_type:
                item['timestamp_desc'] = 'Last Active Time'
                item['data_type'] = 'chrome:session:tab_last_active'
                item['message'] = f'{row_type}: {item.get("value", "")}'
            else:
                item['timestamp_desc'] = 'Navigation Time'
                item['data_type'] = 'chrome:session:navigation'
                item['message'] = f"{item.get('url', '')} ({item.get('title', '')})"

            # Serialize page_state as structured JSON for JSONL output
            if item.get('page_state') and item['page_state'].top_frame:
                ps = item['page_state']
                tf = ps.top_frame
                ps_dict = {'version': ps.version}

                if ps.referenced_files:
                    ps_dict['referenced_files'] = ps.referenced_files

                frame_dict = {}
                if tf.url:
                    frame_dict['url'] = tf.url
                if tf.referrer:
                    frame_dict['referrer'] = tf.referrer
                if tf.state_object:
                    frame_dict['state_object'] = tf.state_object
                if tf.scroll_offset_x or tf.scroll_offset_y:
                    frame_dict['scroll_offset'] = {'x': tf.scroll_offset_x, 'y': tf.scroll_offset_y}
                if tf.page_scale_factor and tf.page_scale_factor != 1.0:
                    frame_dict['page_scale_factor'] = tf.page_scale_factor
                if tf.initiator_origin:
                    frame_dict['initiator_origin'] = tf.initiator_origin
                if tf.form_elements:
                    frame_dict['form_elements'] = [
                        {'name': fe.name, 'type': fe.type, 'values': fe.values}
                        for fe in tf.form_elements
                    ]
                if tf.http_body:
                    body_dict = {
                        'contains_passwords': tf.http_body.contains_passwords,
                        'http_content_type': tf.http_body.http_content_type,
                    }
                    elements = []
                    for el in tf.http_body.elements:
                        if el.element_type == 0 and el.data:
                            elements.append({'type': 'data', 'data': el.data.decode('utf-8', errors='replace')})
                        elif el.element_type == 1:
                            elements.append({'type': 'file', 'path': el.file_path,
                                             'offset': el.file_offset, 'length': el.file_length})
                        elif el.element_type == 2:
                            elements.append({'type': 'blob', 'uuid': el.blob_uuid})
                    if elements:
                        body_dict['elements'] = elements
                    frame_dict['http_body'] = body_dict
                if tf.children:
                    frame_dict['children'] = [
                        {'url': c.url, 'referrer': c.referrer, 'initiator_origin': c.initiator_origin}
                        for c in tf.children if c.url
                    ]

                ps_dict['top_frame'] = frame_dict
                item['page_state'] = ps_dict
            elif 'page_state' in item:
                del item['page_state']

            del(item['row_type'], item['name'])
            return item

        if isinstance(obj, Chrome.DownloadItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'File Downloaded'
            item['data_type'] = 'chrome:history:file_downloaded'

            item['message'] = f"{item['url']} " \
                              f"({item['full_path'] if item.get('full_path') else item.get('target_path')}). " \
                              f"Received {item['received_bytes']}/{item['total_bytes']} bytes"

            del(item['row_type'], item['start_time'])
            return item

        if isinstance(obj, Chrome.BrowserExtension):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Not a time'
            item['data_type'] = 'chrome:extension:installed'
            item['source_long'] = 'Chrome Extensions'
            item['url'] = item.get('ext_id')

            item['message'] = f'{item.get("name", "")} ({item.get("version", "")})'

            return item

        if isinstance(obj, Chrome.CookieItem):
            item = HindsightEncoder.base_encoder(obj)

            item['data_type'] = 'chrome:cookie:entry'
            item['source_long'] = 'Chrome Cookies'
            if item['row_type'] == 'cookie (accessed)':
                item['timestamp_desc'] = 'Last Access Time'
            elif item['row_type'] == 'cookie (created)':
                item['timestamp_desc'] = 'Creation Time'
            item['host'] = item['host_key']
            item['cookie_name'] = item['name']
            item['data'] = item['value'] if item['value'] != '<encrypted>' else ''
            item['url'] = item['url'].lstrip('.')
            item['url'] = f'https://{item["url"]}' if item['secure'] else f'http://{item["url"]}'
            if item['expires_utc'] == '1970-01-01T00:00:00+00:00':
                del(item['expires_utc'])
            # Convert these from 1/0 to true/false to match Plaso
            item['secure'] = 'true' if item['secure'] else 'false'
            item['httponly'] = 'true' if item['httponly'] else 'false'
            item['persistent'] = 'true' if item['persistent'] else 'false'

            item['message'] = (f'{item["url"]} ({item["cookie_name"]}) Flags: [HTTP only] = {item["httponly"]} '
                               f'[Persistent] = {item["persistent"]}')

            del(item['creation_utc'], item['last_access_utc'], item['row_type'],
                item['host_key'], item['name'], item['value'])
            return item

        if isinstance(obj, Chrome.AutofillItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Used Time'
            item['data_type'] = 'chrome:autofill:entry'
            item['source_long'] = 'Chrome Autofill'
            item['usage_count'] = item['count']
            item['field_name'] = item['name']

            item['message'] = f'{item["field_name"]}: {item["value"]} (times used: {item["usage_count"]})'

            del(item['name'], item['row_type'], item['count'], item['date_created'])
            return item

        if isinstance(obj, Chrome.BookmarkItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Creation Time'
            item['data_type'] = 'chrome:bookmark:entry'
            item['source_long'] = 'Chrome Bookmarks'

            item['message'] = f'{item["name"]} ({item["url"]}) bookmarked in folder "{item["parent_folder"]}"'

            del(item['value'], item['row_type'], item['date_added'])
            return item

        if isinstance(obj, Chrome.BookmarkFolderItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Creation Time'
            item['data_type'] = 'chrome:bookmark:folder'
            item['source_long'] = 'Chrome Bookmarks'

            item['message'] = f'"{item["name"]}" bookmark folder created in folder "{item["parent_folder"]}"'

            del(item['value'], item['row_type'], item['date_added'])
            return item

        if isinstance(obj, Chrome.LocalStorageItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Not a time'
            item['data_type'] = 'chrome:local_storage:entry'
            item['source_long'] = 'Chrome LocalStorage'
            item['url'] = item['origin'][1:]
            item['state_friendly'] = item.get('state')
            item['state'] = 0 if item.get('state') == 'Deleted' else 1

            item['message'] = f'key: {item["key"]} value: {item["value"]}'

            del (item['row_type'])
            return item

        if isinstance(obj, Chrome.SessionStorageItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Not a time'
            item['data_type'] = 'chrome:session_storage:entry'
            item['source_long'] = 'Chrome Session Storage'
            item['url'] = item['origin']
            item['state_friendly'] = item.get('state')
            item['state'] = 0 if item.get('state') == 'Deleted' else 1

            item['message'] = f'key: {item.get("key", "")} value: {item.get("value", "")}'

            del (item['row_type'])
            return item

        if isinstance(obj, Chrome.IndexedDBItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Not a time'
            item['data_type'] = 'chrome:indexeddb:entry'
            item['source_long'] = 'Chrome IndexedDB'
            item['url'] = item['origin']
            item['state_friendly'] = item.get('state')
            item['state'] = 0 if item.get('state') == 'Deleted' else 1

            item['message'] = (
                f'database: {item.get("database", "")} '
                f'key: {item.get("key", "")} '
                f'value: {item.get("value", "")}'
            )

            del (item['row_type'])
            return item

        if isinstance(obj, Chrome.FileSystemItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Not a time'
            item['data_type'] = 'chrome:file_system:entry'
            item['source_long'] = 'Chrome File System'
            item['url'] = item['origin']
            item['state_friendly'] = item.get('state')
            item['state'] = 0 if item.get('state') == 'Deleted' else 1

            item['message'] = f'key: {item["key"]} value: {item["value"]}'

            del (item['row_type'])
            return item

        if isinstance(obj, Chrome.LoginItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Used Time'
            item['data_type'] = 'chrome:login_item:entry'
            item['source_long'] = 'Chrome Logins'
            item['usage_count'] = item['count']

            item['message'] = f'{item["name"]}: {item["value"]} used on {item["url"]} (total times used: {item["usage_count"]})'

            del (item['row_type'], item['count'], item['date_created'])
            return item

        if isinstance(obj, Chrome.PreferenceItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Update Time'
            item['data_type'] = 'chrome:preferences:entry'
            item['source_long'] = 'Chrome Preferences'
            item['message'] = f'Updated preference: {item["key"]}: {item["value"]})'

            del(item['row_type'], item['name'])
            return item

        if isinstance(obj, Chrome.ExtensionStorageItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Not a time'
            item['data_type'] = 'chrome:extension_storage:entry'
            item['source_long'] = 'Chrome Extension Storage'
            item['url'] = item.get('extension_id')
            item['state_friendly'] = item.get('state')
            item['state'] = 0 if item.get('state') == 'Deleted' else 1

            item['message'] = (
                f'extension: {item.get("extension_name", "")} '
                f'key: {item.get("key", "")} '
                f'value: {item.get("value", "")}'
            )

            del (item['row_type'])
            return item

        if isinstance(obj, Chrome.SyncDataItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Not a time'
            item['data_type'] = 'chrome:sync_data:entry'
            item['source_long'] = 'Chrome Sync Data'
            item['state_friendly'] = item.get('state')
            item['state'] = 0 if item.get('state') == 'Deleted' else 1

            item['message'] = f'key: {item.get("key", "")} value: {item.get("value", "")}'

            del (item['row_type'])
            return item

        if isinstance(obj, Chrome.SiteSetting):
            item = HindsightEncoder.base_encoder(obj)

            if item['key'] == 'Status: Deleted':
                item['timestamp_desc'] = 'Not a time'
            else:
                item['timestamp_desc'] = 'Update Time'

            item['data_type'] = 'chrome:site_setting:entry'
            item['source_long'] = 'Chrome Site Settings'

            if item['key'] == 'Status: Deleted':
                item['message'] = 'Updated site setting (recovered deleted record)'
            else:
                item['message'] = f'Updated site setting: {item["key"]}: {item["value"]})'

            del(item['row_type'], item['name'])
            return item

        if isinstance(obj, WebBrowser.CacheItem):
            item = HindsightEncoder.base_encoder(obj)

            item['timestamp_desc'] = 'Last Visit Time'
            item['data_type'] = 'chrome:cache:entry'
            item['source_long'] = 'Chrome Cache'
            item['original_url'] = item['url']
            item['cache_type'] = item['row_type']

            if item['data_summary'] == '<no data>':
                item['cached_state'] = 'Evicted'
            else:
                item['cached_state'] = 'Cached'

            item['message'] = f'Original URL: {item["original_url"]}'

            if item.get('data'):
                del item['data']

            del item['row_type']
            return item


class AnalysisSession(object):
    def __init__(
            self, input_path=None, profile_paths=None, cache_path=None, browser_type=None, available_input_types=None,
            version=None, display_version=None, output_name=None, log_path=None, no_copy=None, temp_dir=None,
            timezone=None, available_output_formats=None, selected_output_format=None, available_decrypts=None,
            selected_decrypts=None, parsed_artifacts=None, artifacts_display=None, artifacts_counts=None,
            parsed_storage=None, parsed_sync_data=None, plugin_descriptions=None, selected_plugins=None, plugin_results=None,
            hindsight_version=None, preferences=None, originator_guids=None):
        self.input_path = input_path
        self.profile_paths = profile_paths
        self.cache_path = cache_path
        self.browser_type = browser_type
        self.available_input_types = available_input_types
        self.version = version
        self.display_version = display_version
        self.output_name = output_name
        self.log_path = log_path
        self.no_copy = no_copy
        self.temp_dir = temp_dir
        self.timezone = timezone
        self.available_output_formats = available_output_formats
        self.selected_output_format = selected_output_format
        self.available_decrypts = available_decrypts
        self.selected_decrypts = selected_decrypts
        self.parsed_artifacts = parsed_artifacts
        self.artifacts_display = artifacts_display
        self.artifacts_counts = artifacts_counts
        self.parsed_storage = parsed_storage
        self.parsed_extension_data = []
        self.parsed_sync_data = parsed_sync_data
        self.originator_guids = originator_guids
        self.plugin_descriptions = plugin_descriptions
        self.selected_plugins = selected_plugins
        self.plugin_results = plugin_results
        self.hindsight_version = hindsight_version
        self.preferences = preferences
        self.fatal_error = None

        if self.version is None:
            self.version = []

        if self.available_input_types is None:
            self.available_input_types = ['Chrome']

        if self.parsed_artifacts is None:
            self.parsed_artifacts = []

        if self.artifacts_counts is None:
            self.artifacts_counts = {}

        if self.parsed_storage is None:
            self.parsed_storage = []

        if self.parsed_sync_data is None:
            self.parsed_sync_data = []

        if self.originator_guids is None:
            self.originator_guids = {}

        if self.available_output_formats is None:
            self.available_output_formats = ['sqlite', 'jsonl']

        if self.available_decrypts is None:
            self.available_decrypts = {'windows': 0, 'mac': 0, 'linux': 0}

        if self.plugin_results is None:
            self.plugin_results = {}

        if self.preferences is None:
            self.preferences = []

        if __version__:
            self.hindsight_version = __version__

        # Load API keys from config file
        self.api_keys = self.load_api_keys()

        # Try to import modules for different output formats, adding to self.available_output_format array if successful
        try:
            import xlsxwriter
            self.available_output_formats.append('xlsx')
        except ImportError:
            log.warning("Couldn't import module 'xlsxwriter'; XLSX output disabled.")

        # Set output name to default if not set by user
        if self.output_name is None:
            self.output_name = f'Hindsight Report ({time.strftime("%Y-%m-%dT%H-%M-%S")})'

        # Try to import modules for cookie decryption on different OSes.
        # Windows
        try:
            import win32crypt
            self.available_decrypts['windows'] = 1
        except ImportError:
            self.available_decrypts['windows'] = 0

        # Mac OS
        try:
            import keyring
            self.available_decrypts['mac'] = 1
        except ImportError:
            self.available_decrypts['mac'] = 0

        # Linux / Mac OS
        try:
            import Cryptodome.Cipher.AES
            import Cryptodome.Protocol.KDF
            self.available_decrypts['linux'] = 1
        except ImportError:
            self.available_decrypts['linux'] = 0
            self.available_decrypts['mac'] = 0

    @staticmethod
    def load_api_keys():
        """Load API keys from hindsight_config.json.

        Searches the current working directory and the project root for a config file.
        Returns a dict of key names to values (e.g. {'kg_api_key': 'ABC123'}).
        """
        config_locations = [
            os.path.join(os.getcwd(), 'hindsight_config.json'),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'hindsight_config.json'),
        ]
        for config_path in config_locations:
            if os.path.isfile(config_path):
                try:
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                    log.info(f'Loaded config from {config_path}')
                    return config
                except (json.JSONDecodeError, OSError) as e:
                    log.warning(f'Error reading config file {config_path}: {e}')
        return {}

    @staticmethod
    def sum_dict_counts(dict1, dict2):
        """Combine two dicts by summing the values of shared keys"""
        for key, value in list(dict2.items()):
            # Case 1: dict2's value for key is a string (aka: it failed)
            if isinstance(value, str):
                #  The value should only be non-int if it's a Failed message
                if not value.startswith('Fail'):
                    raise ValueError('Unexpected status value')

                dict1[key] = dict1.setdefault(key, 0)

            # Case 2: dict1's value of key is a string (aka: it failed)
            elif isinstance(dict1.get(key), str):
                #  The value should only be non-int if it's a Failed message
                if not dict1.get(key).startswith('Fail'):
                    raise ValueError('Unexpected status value')

                dict1[key] = value

            # Case 3: dict2's value for key is an int, or doesn't exist.
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

    @staticmethod
    def is_profile(base_path, existing_files, warn=False):
        """Log a warning message if any file in `required_files` is missing from
        `existing_files`. Return True if all required files are present.
        """
        is_profile = True
        for required_file in ['History']:
            # This approach (checking the file names) is naive but should work.
            if required_file not in existing_files or not os.path.isfile(os.path.join(base_path, required_file)):
                if warn:
                    log.warning(f"The profile directory {base_path} does not contain the "
                                f"file {required_file}. Analysis may not be very useful.")
                is_profile = False
        return is_profile

    def search_subdirs(self, base_path):
        """Recursively search a path for browser profiles"""
        found_profile_paths = []

        try:
            base_dir_listing = os.listdir(base_path)
        except Exception as e:
            log.warning(f'Unable to read directory; Exception: {e}')
            return found_profile_paths

        if self.is_profile(base_path, base_dir_listing):
            found_profile_paths.append(base_path)
        for item in base_dir_listing:
            item_path = os.path.join(base_path, item)
            if os.path.isdir(item_path) and not os.path.islink(item_path):
                profile_found_in_subdir = self.search_subdirs(item_path)
                if profile_found_in_subdir:
                    found_profile_paths.extend(profile_found_in_subdir)
        return found_profile_paths

    def find_browser_profiles(self, base_path):
        """Search a path for browser profiles (only Chromium-based at the moment)."""
        found_profile_paths = []
        base_dir_listing = os.listdir(base_path)

        # The 'History' SQLite file is kind of the minimum required for most
        # Chrome analysis. Warn if not present.
        if self.is_profile(base_path, base_dir_listing, warn=True):
            found_profile_paths.append(base_path)

        else:
            # Only search sub dirs if the current dir is not a Profile (Profiles are not nested).
            found_profile_paths.extend(self.search_subdirs(base_path))

        # If we did not find any valid Profiles, attempt to process the input
        # path as a Profile
        if not found_profile_paths:
            log.warning("No Profile paths found; processing input path as a Profile")
            found_profile_paths = [base_path]

        log.debug("Profile paths: " + str(found_profile_paths))
        return found_profile_paths

    def generate_display_version(self):
        self.version = sorted(self.version)
        if self.version is not None and len(self.version) >= 1:
            if self.version[0] != self.version[-1]:
                self.display_version = f'{self.version[0]}-{self.version[-1]}'
            else:
                self.display_version = self.version[0]
        else:
            self.display_version = "None"

    def run(self):
        if self.selected_output_format is None:
            self.selected_output_format = self.available_output_formats[-1]

        # If the timezone exists as a string, convert it to a tzinfo object
        if self.timezone is not None and isinstance(self.timezone, str):
            try:
                self.timezone = ZoneInfo(self.timezone)
            except ZoneInfoNotFoundError:
                log.warning("Couldn't understand timezone; using UTC.")
                self.timezone = datetime.timezone.utc
        elif self.timezone is None:
            self.timezone = datetime.timezone.utc

        log.debug("Options: " + str(self.__dict__))

        # Analysis start time
        log.info("Starting analysis")

        log.info(f'Reading files from {self.input_path}')
        try:
            input_listing = os.listdir(self.input_path)
        except OSError as e:
            fail_message = f'Unable to read input directory; {e}'
            log.error(fail_message)
            self.fatal_error = fail_message
            return False
        log.debug("Input directory contents: " + str(input_listing))

        # Search input directory for browser profiles to analyze
        input_profiles = self.find_browser_profiles(self.input_path)
        log.info(f' - Found {len(input_profiles)} browser profile(s): {input_profiles}')
        self.profile_paths = input_profiles

        # Make sure the input is what we're expecting
        assert isinstance(self.profile_paths, list)
        assert len(self.profile_paths) >= 1

        for found_profile_path in self.profile_paths:

            if self.browser_type == "Chrome":
                browser_analysis = Chrome(found_profile_path, available_decrypts=self.available_decrypts,
                                          cache_path=self.cache_path, timezone=self.timezone,
                                          no_copy=self.no_copy, temp_dir=self.temp_dir,
                                          originator_guids=self.originator_guids)
                browser_analysis.process(api_keys=self.api_keys)
                self.parsed_artifacts.extend(browser_analysis.parsed_artifacts)
                self.parsed_storage.extend(browser_analysis.parsed_storage)
                self.parsed_extension_data.extend(browser_analysis.parsed_extension_data)
                self.parsed_sync_data.extend(browser_analysis.parsed_sync_data)
                self.artifacts_counts = self.sum_dict_counts(self.artifacts_counts, browser_analysis.artifacts_counts)
                self.artifacts_display = browser_analysis.artifacts_display
                self.version.extend(browser_analysis.version)
                self.display_version = browser_analysis.display_version
                self.preferences.extend(browser_analysis.preferences)
                if hasattr(browser_analysis, 'session_structure'):
                    if not hasattr(self, 'session_structures'):
                        self.session_structures = []
                    self.session_structures.append({
                        'profile': found_profile_path,
                        **browser_analysis.session_structure
                    })

                for item in browser_analysis.__dict__:
                    if isinstance(browser_analysis.__dict__[item], dict):
                        try:
                            # If the browser_analysis attribute has 'presentation' and 'data' subkeys, promote from
                            if browser_analysis.__dict__[item].get('presentation') and \
                                    browser_analysis.__dict__[item].get('data'):
                                self.promote_object_to_analysis_session(item, browser_analysis.__dict__[item])
                        except Exception as e:
                            log.info(f'Exception occurred while analyzing {item} for analysis session promotion: {e}')

            elif self.browser_type == "Brave":
                browser_analysis = Brave(found_profile_path, timezone=self.timezone)
                browser_analysis.process()
                self.parsed_artifacts = browser_analysis.parsed_artifacts
                self.parsed_storage.extend(browser_analysis.parsed_storage)
                self.artifacts_counts = browser_analysis.artifacts_counts
                self.artifacts_display = browser_analysis.artifacts_display
                self.version = browser_analysis.version
                self.display_version = browser_analysis.display_version

                for item in browser_analysis.__dict__:
                    if isinstance(browser_analysis.__dict__[item], dict):
                        try:
                            # If the browser_analysis attribute has 'presentation' and 'data' subkeys, promote from
                            if browser_analysis.__dict__[item].get('presentation') and \
                                    browser_analysis.__dict__[item].get('data'):
                                self.promote_object_to_analysis_session(item, browser_analysis.__dict__[item])
                        except Exception as e:
                            log.info(f'Exception occurred while analyzing {item} for analysis session promotion: {e}')

        self.apply_originator_visit_sources()
        self.generate_display_version()
        return True

    def apply_originator_visit_sources(self):
        if not self.originator_guids:
            return

        updated_count = 0
        for item in self.parsed_artifacts:
            if not isinstance(item, Chrome.URLItem):
                continue

            cache_guid = getattr(item, 'originator_cache_guid', None)
            if not cache_guid:
                continue

            cache_entry = self.originator_guids.get(cache_guid)
            if not cache_entry:
                continue

            if item.visit_source not in (None, 'Synced', 0):
                continue

            device_parts = []
            hostname = cache_entry.get('hostname')
            os_type = cache_entry.get('os_type')
            model = cache_entry.get('model')
            if os_type:
                device_parts.append(os_type)
            if model:
                device_parts.append(model)

            device_suffix = f" ({', '.join(device_parts)})" if device_parts else ""
            if hostname:
                item.visit_source = f'Synced from "{hostname}"{device_suffix}'
            else:
                item.visit_source = f"Synced{device_suffix}"
            updated_count += 1

        if updated_count:
            log.info(f' - Applied originator cache info to {updated_count} URL visit sources')

    def run_plugins(self):
        log.info("Selected plugins: " + str(self.selected_plugins))
        completed_plugins = []
        plugin_rows = []
        console = rich.console.Console()

        def format_plugin_name(name, version):
            text = rich.text.Text()
            text.append(f"{name} ")
            text.append(f"(v{version}):", style="dim")
            return text

        def format_plugin_result(items):
            text = rich.text.Text()
            text.append("- ", style="dim")
            text.append(f"{items}")
            text.append(" -", style="dim")
            return text

        def running_status():
            return rich.spinner.Spinner("dots")

        def build_plugin_table():
            table = rich.table.Table(show_header=False, box=None, expand=False)
            table.add_column(justify="right", min_width=44)
            table.add_column(justify="center", min_width=30)
            for row in plugin_rows:
                table.add_row(*row)
            return rich.align.Align.center(table)

        def update_plugin_table(live):
            if live:
                live.update(build_plugin_table())

        console.rule("Running Plugins", style="green")
        console.print()

        with rich.live.Live(build_plugin_table(), console=console, refresh_per_second=6) as live:
            for plugin in self.selected_plugins:

                # First check built-in plugins that ship with Hindsight
                for standard_plugin in pyhindsight.plugins.__all__:
                    # Check if the standard plugin is the selected_plugin we're looking for
                    if standard_plugin == plugin:
                        # Check to see if we've already run this plugin (likely from a different path)
                        if plugin in completed_plugins:
                            log.info(f" - Skipping '{plugin}'; a plugin with that name has run already")
                            continue

                        log.info(f" - Loading '{plugin}' [standard plugin]")
                        try:
                            module = importlib.import_module(f"pyhindsight.plugins.{plugin}")
                        except ImportError as e:
                            log.error(f" - Error: {e}")
                            plugin_rows.append((format_plugin_name(plugin, "unknown"), rich.text.Text("- import failed -", style="red")))
                            update_plugin_table(live)
                            continue
                        try:
                            log.info(f" - Running '{module.friendlyName}' plugin")
                            plugin_rows.append((format_plugin_name(module.friendlyName, module.version), running_status()))
                            update_plugin_table(live)
                            parsed_items = module.plugin(self)
                            plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), format_plugin_result(parsed_items))
                            update_plugin_table(live)
                            self.plugin_results[plugin] = [module.friendlyName, module.version, parsed_items]
                            log.info(f" - Completed; {parsed_items}")
                            completed_plugins.append(plugin)
                            break
                        except Exception as e:
                            plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), rich.text.Text("- failed -", style="red"))
                            update_plugin_table(live)
                            self.plugin_results[plugin] = [module.friendlyName, module.version, 'failed']
                            log.info(f" - Failed; {e}")

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
                                if custom_plugin.endswith(".py") and custom_plugin[0] != '_':
                                    custom_plugin = custom_plugin.replace(".py", "")

                                    if custom_plugin == plugin:
                                        # Check to see if we've already run this plugin (likely from a different path)
                                        if plugin in completed_plugins:
                                            log.info(f" - Skipping '{plugin}'; a plugin with that name has run already")
                                            continue

                                        log.debug(f" - Loading '{plugin}' [custom plugin]")
                                        try:
                                            module = __import__(plugin)
                                        except ImportError as e:
                                            log.error(f" - Error: {e}")
                                            plugin_rows.append((format_plugin_name(plugin, "unknown"), rich.text.Text("- import failed -", style="red")))
                                            update_plugin_table(live)
                                            continue
                                        try:
                                            log.info(f" - Running '{module.friendlyName}' plugin")
                                            plugin_rows.append((format_plugin_name(module.friendlyName, module.version), running_status()))
                                            update_plugin_table(live)
                                            parsed_items = module.plugin(self)
                                            plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), format_plugin_result(parsed_items))
                                            update_plugin_table(live)
                                            self.plugin_results[plugin] = [module.friendlyName, module.version, parsed_items]
                                            log.info(f" - Completed; {parsed_items}")
                                            completed_plugins.append(plugin)
                                        except Exception as e:
                                            plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), rich.text.Text("- failed -", style="red"))
                                            update_plugin_table(live)
                                            self.plugin_results[plugin] = [module.friendlyName, module.version, 'failed']
                                            log.info(f" - Failed; {e}")
                        except Exception as e:
                            log.debug(f' - Error loading plugins ({e})')
                            console.print('  - Error loading plugins')
                        finally:
                            # Remove the current plugin location from the system path, so we don't loop over it again
                            sys.path.remove(potential_plugin_path)

    def generate_excel(self, output_object):
        import xlsxwriter
        workbook = xlsxwriter.Workbook(output_object, {'in_memory': True, 'strings_to_urls': False})

        # Track used sheet names to avoid duplicates
        used_sheet_names = set()

        def get_unique_sheet_name(base_name):
            """Return a unique sheet name, appending a number if needed."""
            # Excel sheet names are limited to 31 characters
            base_name = base_name[:31]
            name = base_name
            counter = 2
            while name.lower() in used_sheet_names:
                suffix = f" ({counter})"
                # Make room for the suffix within the 31 char limit
                name = base_name[:31 - len(suffix)] + suffix
                counter += 1
            used_sheet_names.add(name.lower())
            return name

        w = workbook.add_worksheet('Timeline')
        used_sheet_names.add('timeline')

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

        ################################
        # Timeline worksheet
        ################################

        # Title bar
        w.merge_range('A1:I1', f'Hindsight Internet History Forensics (v{__version__}) - Timeline', title_header_format)
        w.merge_range('J1:W1', 'URL Visit Specific', center_header_format)
        w.merge_range('X1:Z1', 'Download Specific', center_header_format)
        w.merge_range('AA1:AC1', 'Cache Specific', center_header_format)

        # Write column headers
        w.write(1, 0, 'Type', header_format)
        w.write(1, 1, f'Timestamp ({self.timezone})', header_format)
        w.write(1, 2, 'URL', header_format)
        w.write(1, 3, 'Title / Name / Status', header_format)
        w.write(1, 4, 'Data / Value / Path', header_format)
        w.write(1, 5, 'Interpretation', header_format)
        w.write(1, 6, 'Profile', header_format)
        w.write(1, 7, 'Source Item', header_format)
        w.write(1, 8, 'Visit Source', header_format)
        w.write(1, 9, 'Visit ID', header_format)
        w.write(1, 10, 'From Visit', header_format)
        w.write(1, 11, 'Opener Visit', header_format)
        w.write(1, 12, 'Visit Duration', header_format)
        w.write(1, 13, 'Visit Count', header_format)
        w.write(1, 14, 'Typed Count', header_format)
        w.write(1, 15, 'URL Hidden', header_format)
        w.write(1, 16, 'Transition', header_format)
        w.write(1, 17, 'Categories', header_format)
        w.write(1, 18, 'Entities', header_format)
        w.write(1, 19, 'Cluster', header_format)
        w.write(1, 20, 'Window ID', header_format)
        w.write(1, 21, 'Tab ID', header_format)
        w.write(1, 22, 'Response Code', header_format)
        w.write(1, 23, 'Interrupt Reason', header_format)
        w.write(1, 24, 'Danger Type', header_format)
        w.write(1, 25, 'Opened?', header_format)
        w.write(1, 26, 'ETag', header_format)
        w.write(1, 27, 'Last Modified', header_format)
        w.write(1, 28, 'All HTTP Headers', header_format)

        # Set column widths
        w.set_column('A:A', 16)  # Type
        w.set_column('B:B', 21)  # Date
        w.set_column('C:C', 60)  # URL
        w.set_column('D:D', 25)  # Title / Name / Status
        w.set_column('E:E', 60)  # Data / Value / Path
        w.set_column('F:F', 40)  # Interpretation
        w.set_column('G:G', 20)  # Profile
        w.set_column('H:H', 20)  # Source Item
        w.set_column('I:I', 14)  # Visit Source

        # URL Visit Specific
        w.set_column('M:M', 14)  # Visit Duration
        w.set_column('N:P', 6)   # Visit Count, Typed Count, Hidden
        w.set_column('Q:Q', 12)  # Transition
        w.set_column('R:R', 18)  # Categories
        w.set_column('S:S', 18)  # Entities
        w.set_column('T:T', 15)  # Cluster
        w.set_column('U:U', 12)  # Window ID
        w.set_column('V:V', 12)  # Tab ID
        w.set_column('W:W', 12)  # Response Code

        # Download Specific
        w.set_column('X:X', 12)  # Interrupt Reason
        w.set_column('Y:Y', 24)  # Danger Type
        w.set_column('Z:Z', 12)  # Opened

        # Common between Downloads and Cache
        w.set_column('AA:AA', 12)  # ETag
        w.set_column('AB:AB', 27)  # Last Modified

        # Cache Specific
        w.set_column('AC:AC', 30)  # HTTP Headers

        # Start at the row after the headers and begin writing out the items in parsed_artifacts
        row_number = 2
        seen_session_form_data = set()  # dedup key: (url, name, type, value)
        for item in sorted(self.parsed_artifacts):
            try:
                if item.row_type.startswith("url"):
                    w.write_string(row_number, 0, item.row_type, black_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), black_date_format)  # date
                    w.write_string(row_number, 2, item.url, black_url_format)  # URL
                    w.write_string(row_number, 3, item.name, black_field_format)  # Title
                    w.write(row_number, 4, "", black_value_format)  # Data / Value / Path
                    w.write(row_number, 5, item.interpretation, black_value_format)  # Interpretation
                    w.write(row_number, 6, item.profile, black_type_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', black_type_format)  # Source Item
                    w.write(row_number, 8, item.visit_source, black_type_format)  # Visit Source
                    w.write(row_number, 9, item.visit_id, black_flag_format)
                    w.write(row_number, 10, item.from_visit, black_flag_format)
                    w.write(row_number, 11, item.opener_visit, black_flag_format)
                    w.write(row_number, 12, item.visit_duration, black_flag_format)
                    w.write(row_number, 13, item.visit_count, black_flag_format)
                    w.write(row_number, 14, item.typed_count, black_flag_format)
                    w.write(row_number, 15, item.hidden, black_flag_format)
                    w.write(row_number, 16, item.transition_friendly, black_trans_format)
                    w.write(row_number, 17, item.categories_str or "", black_value_format)  # Categories
                    w.write(row_number, 18, item.entities_str or "", black_value_format)  # Entities
                    w.write(row_number, 19, item.cluster_str or "", black_value_format)  # Cluster
                    if getattr(item, 'window_id', None) is not None:
                        w.write(row_number, 20, item.window_id, black_value_format)  # Window ID
                    if getattr(item, 'tab_id', None) is not None:
                        w.write(row_number, 21, item.tab_id, black_value_format)  # Tab ID
                    if getattr(item, 'response_code', None) is not None:
                        w.write(row_number, 22, item.response_code, black_value_format)  # Response Code

                elif item.row_type.startswith("media"):
                    w.write_string(row_number, 0, item.row_type, blue_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), blue_date_format)  # date
                    w.write_string(row_number, 2, item.url, blue_url_format)  # URL
                    w.write_string(row_number, 3, item.title, blue_field_format)  # Title
                    if item.source_title:
                        media_message = f'Watched{item.watch_time} on {item.source_title} '\
                                        f'(ending at {item.position}/{item.media_duration}) '\
                                        f'[has_video: {item.has_video}; has_audio: {item.has_audio}]'
                    else:
                        media_message = f'Watched{item.watch_time} ' \
                                        f'[has_video: {item.has_video}; has_audio: {item.has_audio}]'
                    w.write(row_number, 4, media_message, blue_value_format)
                    w.write(row_number, 5, item.interpretation, blue_value_format)  # Interpretation
                    w.write(row_number, 6, item.profile, blue_type_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', blue_type_format)  # Source Item

                elif item.row_type.startswith("autofill"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 3, item.name, red_field_format)  # autofill field
                    w.write_string(row_number, 4, item.value, red_value_format)  # autofill value
                    w.write(row_number, 6, item.profile, red_type_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', red_type_format)  # Source Item

                elif item.row_type.startswith("download"):
                    w.write_string(row_number, 0, item.row_type, green_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), green_date_format)  # date
                    w.write_string(row_number, 2, item.url, green_url_format)  # download URL
                    w.write_string(row_number, 3, item.status_friendly, green_field_format)  # % complete
                    w.write_string(row_number, 4, item.value, green_value_format)  # download path
                    w.write_string(row_number, 5, "", green_field_format)  # Interpretation (chain?)
                    w.write(row_number, 6, item.profile, green_type_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', green_type_format)  # Source Item
                    w.write(row_number, 23, item.interrupt_reason_friendly, green_value_format)  # interrupt reason
                    w.write(row_number, 24, item.danger_type_friendly, green_value_format)  # danger type
                    open_friendly = ""
                    if item.opened == 1:
                        open_friendly = 'Yes'
                    elif item.opened == 0:
                        open_friendly = 'No'
                    w.write_string(row_number, 25, open_friendly, green_value_format)  # opened
                    w.write(row_number, 26, item.etag, green_value_format)  # ETag
                    w.write(row_number, 27, item.last_modified, green_value_format)  # Last Modified

                elif item.row_type.startswith("bookmark folder"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 3, item.name, red_value_format)  # bookmark name
                    w.write_string(row_number, 4, item.value, red_value_format)  # bookmark folder
                    w.write(row_number, 6, item.profile, red_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', red_value_format)  # Source Item

                elif item.row_type.startswith("bookmark"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 2, item.url, red_url_format)  # URL
                    w.write_string(row_number, 3, item.name, red_value_format)  # bookmark name
                    w.write_string(row_number, 4, item.value, red_value_format)  # bookmark folder
                    w.write(row_number, 6, item.profile, red_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', red_value_format)  # Source Item

                elif item.row_type.startswith("cookie"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    w.write_string(row_number, 3, item.name, gray_field_format)  # cookie name
                    w.write_string(row_number, 4, item.value, gray_value_format)  # cookie value
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # cookie interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', gray_value_format)  # Source Item

                elif item.row_type.startswith("cache"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    try:
                        w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    except Exception as e:
                        print(e, item.url, item.location)
                    w.write_string(row_number, 3, item.data_summary, gray_field_format)   # type (size) // image/jpeg (35 bytes)
                    w.write_string(row_number, 4, item.locations, gray_value_format)
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # cookie interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', gray_value_format)  # Source Item
                    w.write(row_number, 26, item.etag, gray_value_format)  # ETag
                    w.write(row_number, 27, item.last_modified, gray_value_format)  # Last Modified
                    w.write(row_number, 28, item.http_headers_str, gray_value_format)  # headers

                elif item.row_type.startswith("local storage"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    w.write_string(row_number, 3, item.name, gray_field_format)  # cookie name
                    w.write_string(row_number, 4, item.value, gray_value_format)  # cookie value
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # cookie interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', gray_value_format)  # Source Item

                elif item.row_type.startswith("login"):
                    w.write_string(row_number, 0, item.row_type, red_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)  # date
                    w.write_string(row_number, 2, item.url, red_url_format)  # URL
                    w.write_string(row_number, 3, item.name, red_field_format)  # form field name
                    w.write_string(row_number, 4, item.value, red_value_format)  # username or pw value
                    w.write_string(row_number, 5, item.interpretation, red_value_format)  # interpretation
                    w.write(row_number, 6, item.profile, red_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', red_value_format)  # Source Item

                elif item.row_type.startswith("session"):
                    w.write_string(row_number, 0, item.row_type, blue_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), blue_date_format)  # date
                    w.write_string(row_number, 2, item.url or '', blue_url_format)  # URL
                    w.write_string(row_number, 3, item.name or '', blue_field_format)  # title
                    w.write_string(row_number, 4, item.value or '', blue_value_format)  # value
                    w.write(row_number, 5, item.interpretation, blue_value_format)  # interpretation
                    w.write(row_number, 6, item.profile, blue_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', blue_value_format)  # Source Item
                    w.write(row_number, 16, getattr(item, 'transition_type', ''), blue_field_format)  # Transition
                    # Session-specific: Window ID, Tab ID, Response Code
                    session_id = getattr(item, 'session_id', None)
                    http_status = getattr(item, 'http_status', None)
                    if http_status is not None:
                        w.write(row_number, 22, http_status, blue_value_format)  # Response Code

                    is_window_event = 'window' in item.row_type
                    if session_id is not None:
                        if is_window_event:
                            w.write(row_number, 20, session_id, blue_value_format)  # Window ID
                        else:
                            w.write(row_number, 21, session_id, blue_value_format)  # Tab ID
                            # Look up window_id from session structure
                            if hasattr(self, 'session_structures') and self.session_structures:
                                for sess in self.session_structures:
                                    tab_meta = sess.get('tabs', {}).get(session_id)
                                    if tab_meta and tab_meta.get('window_id') is not None:
                                        w.write(row_number, 20, tab_meta['window_id'], blue_value_format)
                                        break

                    # Emit additional red "session (form data)" rows for interesting form elements
                    interesting_form_types = ('text', 'textarea', 'password', 'file', 'search', 'email', 'url')
                    page_state = getattr(item, 'page_state', None)
                    if page_state and page_state.top_frame and page_state.top_frame.form_elements:
                        for fe in page_state.top_frame.form_elements:
                            if fe.type not in interesting_form_types:
                                continue
                            if not fe.values or not any(v.strip() for v in fe.values):
                                continue
                            form_name = fe.name or '(unnamed)'
                            form_value = fe.values[0]
                            # Deduplicate: skip if same URL + name + value + timestamp already emitted
                            dedup_key = (item.url, form_name, fe.type, form_value, friendly_date(item.timestamp))
                            if dedup_key in seen_session_form_data:
                                continue
                            seen_session_form_data.add(dedup_key)
                            row_number += 1
                            w.write_string(row_number, 0, 'session (form data)', red_type_format)
                            w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)
                            w.write_string(row_number, 2, item.url or '', red_url_format)
                            w.write_string(row_number, 3, f'{form_name} [{fe.type}]', red_field_format)
                            w.write_string(row_number, 4, form_value, red_value_format)
                            w.write(row_number, 6, item.profile, red_type_format)
                            w.write(row_number, 7, item.source_item or '', red_type_format)  # Source Item

                        # Also check child iframes for file uploads
                        if page_state and page_state.top_frame and page_state.top_frame.children:
                            for child in page_state.top_frame.children:
                                if not child or not child.form_elements:
                                    continue
                                for fe in child.form_elements:
                                    if fe.type != 'file' or not fe.values or not any(v.strip() for v in fe.values):
                                        continue
                                    form_value = fe.values[0]
                                    dedup_key = (item.url, '(iframe file)', 'file', form_value, friendly_date(item.timestamp))
                                    if dedup_key in seen_session_form_data:
                                        continue
                                    seen_session_form_data.add(dedup_key)
                                    row_number += 1
                                    w.write_string(row_number, 0, 'session (form data)', red_type_format)
                                    w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)
                                    w.write_string(row_number, 2, child.url or item.url or '', red_url_format)
                                    w.write_string(row_number, 3, f'(iframe file) [file]', red_field_format)
                                    w.write_string(row_number, 4, form_value, red_value_format)
                                    w.write(row_number, 6, item.profile, red_type_format)
                                    w.write(row_number, 7, item.source_item or '', red_type_format)  # Source Item

                        # Emit referenced_files as emphasis rows (file paths referenced by the page)
                        if page_state and page_state.referenced_files:
                            for ref_file in page_state.referenced_files:
                                if not ref_file or not ref_file.strip():
                                    continue
                                dedup_key = (item.url, '(referenced file)', 'file', ref_file, friendly_date(item.timestamp))
                                if dedup_key in seen_session_form_data:
                                    continue
                                seen_session_form_data.add(dedup_key)
                                row_number += 1
                                w.write_string(row_number, 0, 'session (form data)', red_type_format)
                                w.write(row_number, 1, friendly_date(item.timestamp), red_date_format)
                                w.write_string(row_number, 2, item.url or '', red_url_format)
                                w.write_string(row_number, 3, '(referenced file) [file]', red_field_format)
                                w.write_string(row_number, 4, ref_file, red_value_format)
                                w.write(row_number, 6, item.profile, red_type_format)
                                w.write(row_number, 7, item.source_item or '', red_type_format)  # Source Item

                elif item.row_type.startswith(("permission action", "profile creation", "notification")):
                    w.write_string(row_number, 0, item.row_type, blue_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), blue_date_format)  # date
                    w.write_string(row_number, 2, item.url, blue_url_format)  # URL
                    w.write_string(row_number, 3, item.name, blue_field_format)  # key
                    w.write_string(row_number, 4, item.value, blue_value_format)  # value
                    w.write(row_number, 5, item.interpretation, blue_value_format)  # interpretation
                    w.write(row_number, 6, item.profile, blue_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', blue_value_format)  # Source Item

                elif item.row_type.startswith("preference"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    w.write_string(row_number, 3, item.name, gray_field_format)  # form field name
                    w.write_string(row_number, 4, item.value, gray_value_format)  # value
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', gray_value_format)  # Source Item

                elif item.row_type.startswith("site setting"):
                    w.write_string(row_number, 0, item.row_type, gray_type_format)  # record_type
                    w.write(row_number, 1, friendly_date(item.timestamp), gray_date_format)  # date
                    w.write_string(row_number, 2, item.url, gray_url_format)  # URL
                    w.write_string(row_number, 3, item.name, gray_field_format)  # form field name
                    w.write_string(row_number, 4, item.value, gray_value_format)  # username or pw value
                    w.write(row_number, 5, item.interpretation, gray_value_format)  # interpretation
                    w.write(row_number, 6, item.profile, gray_value_format)  # Profile
                    w.write(row_number, 7, item.source_item or '', gray_value_format)  # Source Item

                if friendly_date(item.timestamp) < '1970-01-02':
                    w.set_row(row_number, options={'hidden': True})

            except Exception as e:
                log.error(f'Failed to write row to XLSX: {e}')

            row_number += 1

        # Formatting
        w.freeze_panes(2, 0)  # Freeze top row
        w.autofilter(1, 0, row_number, 28)  # Add autofilter
        w.filter_column('B', 'Timestamp > 1970-01-02')

        ##############################
        # Storage worksheet
        ##############################
        s = workbook.add_worksheet('Storage')
        used_sheet_names.add('storage')
        # Title bar
        s.merge_range('A1:G1', f'Hindsight Internet History Forensics (v{__version__}) - Storage', title_header_format)
        s.merge_range('H1:K1', 'Backing Database Specific', center_header_format)
        s.merge_range('L1:N1', 'FileSystem Specific', center_header_format)

        # Write column headers
        s.write(1, 0, 'Type', header_format)
        s.write(1, 1, 'Origin', header_format)
        s.write(1, 2, 'Key', header_format)
        s.write(1, 3, 'Value', header_format)
        s.write(1, 4, f'Modification Time ({self.timezone})', header_format)
        s.write(1, 5, 'Interpretation', header_format)
        s.write(1, 6, 'Profile', header_format)
        s.write(1, 7, 'Source Path', header_format)
        s.write(1, 8, 'Database', header_format)
        s.write(1, 9, 'Sequence', header_format)
        s.write(1, 10, 'State', header_format)
        s.write(1, 11, 'File Exists?', header_format)
        s.write(1, 12, 'File Size (bytes)', header_format)
        s.write(1, 13, 'File Type (Confidence %)', header_format)

        # Set column widths
        s.set_column('A:A', 16)  # Type
        s.set_column('B:B', 30)  # Origin
        s.set_column('C:C', 35)  # Key
        s.set_column('D:D', 60)  # Value
        s.set_column('E:E', 16)  # Mod Time
        s.set_column('F:F', 50)  # Interpretation
        s.set_column('G:G', 50)  # Profile
        s.set_column('H:H', 50)  # Source Path
        s.set_column('I:I', 16)  # Database
        s.set_column('J:J', 8)   # Seq
        s.set_column('K:K', 8)   # State
        s.set_column('L:L', 8)   # Exists
        s.set_column('M:M', 16)  # Size
        s.set_column('N:N', 25)  # Type

        # Start at the row after the headers, and begin writing out the items in parsed_artifacts
        row_number = 2
        for item in self.parsed_storage:
            try:
                if item.row_type.startswith("file system"):
                    s.write_string(row_number, 0, item.row_type, black_type_format)
                    s.write_string(row_number, 1, item.origin, black_url_format)
                    s.write_string(row_number, 2, item.key, black_field_format)
                    s.write_string(row_number, 3, item.value, black_value_format)
                    s.write(row_number, 4, friendly_date(item.last_modified), black_date_format)
                    s.write(row_number, 5, item.interpretation, black_value_format)
                    s.write(row_number, 6, item.profile, black_value_format)
                    s.write(row_number, 7, item.source_path, black_value_format)
                    s.write_number(row_number, 9, item.seq, black_value_format)
                    s.write_string(row_number, 10, item.state, black_value_format)
                    s.write(row_number, 11, item.file_exists, black_value_format)
                    s.write(row_number, 12, item.file_size, black_value_format)
                    s.write(row_number, 13, item.magic_results, black_value_format)

                elif item.row_type.startswith(("local storage", "session storage")):
                    s.write_string(row_number, 0, item.row_type, black_type_format)
                    s.write_string(row_number, 1, item.origin, black_url_format)
                    s.write_string(row_number, 2, item.key, black_field_format)
                    s.write(row_number, 3, item.value, black_value_format)
                    s.write(row_number, 4, friendly_date(item.last_modified), black_date_format)
                    s.write(row_number, 5, item.interpretation, black_value_format)
                    s.write(row_number, 6, item.profile, black_value_format)
                    s.write(row_number, 7, item.source_path, black_value_format)
                    s.write_number(row_number, 9, item.seq, black_value_format)
                    s.write_string(row_number, 10, item.state, black_value_format)

                elif item.row_type.startswith("indexeddb"):
                    s.write_string(row_number, 0, item.row_type, black_type_format)
                    s.write_string(row_number, 1, item.origin, black_url_format)
                    s.write_string(row_number, 2, item.key, black_field_format)
                    s.write_string(row_number, 3, item.value, black_value_format)
                    s.write(row_number, 5, item.interpretation, black_value_format)
                    s.write(row_number, 6, item.profile, black_value_format)
                    s.write(row_number, 7, item.source_path, black_value_format)
                    s.write(row_number, 8, item.database, black_value_format)
                    s.write_number(row_number, 9, item.seq, black_value_format)
                    s.write_string(row_number, 10, item.state, black_value_format)

                else:
                    s.write_string(row_number, 0, item.row_type, black_type_format)
                    s.write_string(row_number, 1, item.origin, black_url_format)
                    s.write_string(row_number, 2, item.key, black_field_format)
                    s.write_string(row_number, 3, item.value, black_value_format)
                    s.write(row_number, 5, item.interpretation, black_value_format)
                    s.write(row_number, 6, item.profile, black_value_format)
                    s.write(row_number, 7, item.source_path, black_value_format)
                    # s.write(row_number, 8, item.database, black_value_format)
                    s.write_number(row_number, 9, item.seq, black_value_format)
                    s.write_string(row_number, 10, item.state, black_value_format)

            except Exception as e:
                log.error(f'Failed to write row to XLSX: {e}')

            row_number += 1

        # Formatting
        s.freeze_panes(2, 0)  # Freeze top row
        s.autofilter(1, 0, row_number, 12)  # Add autofilter

        #########################################
        # Extension Data worksheet
        #########################################
        ext = workbook.add_worksheet('Extension Data')
        used_sheet_names.add('extension data')
        # Title bar
        ext.merge_range('A1:G1', f'Hindsight Internet History Forensics (v{__version__}) - Extension Data', title_header_format)
        ext.merge_range('H1:L1', 'Backing LevelDB Specific', center_header_format)

        # Write column headers
        ext.write(1, 0, 'Type', header_format)
        ext.write(1, 1, 'Extension Name', header_format)
        ext.write(1, 2, 'Extension ID', header_format)
        ext.write(1, 3, 'Key', header_format)
        ext.write(1, 4, 'Value', header_format)
        ext.write(1, 5, 'Interpretation', header_format)
        ext.write(1, 6, 'Profile', header_format)
        ext.write(1, 7, 'Source Path', header_format)
        ext.write(1, 8, 'Offset', header_format)
        ext.write(1, 9, 'Sequence', header_format)
        ext.write(1, 10, 'State', header_format)
        ext.write(1, 11, 'Was Compressed', header_format)

        # Set column widths
        ext.set_column('A:A', 16)  # Type
        ext.set_column('B:B', 30)  # ID
        ext.set_column('C:C', 30)  # Name
        ext.set_column('D:D', 35)  # Key
        ext.set_column('E:E', 70)  # Value
        ext.set_column('F:F', 40)  # Interpretation
        ext.set_column('G:G', 50)  # Profile
        ext.set_column('H:H', 50)  # Source Path
        ext.set_column('I:I', 12)  # Offset
        ext.set_column('J:J', 8)   # Seq
        ext.set_column('K:K', 8)   # State
        ext.set_column('L:L', 8)   # Was Compressed


        # Start at the row after the headers, and begin writing out the items in parsed_artifacts
        row_number = 2
        for item in self.parsed_extension_data:
            try:
                if item.row_type:
                    ext.write_string(row_number, 0, item.row_type, black_type_format)
                    ext.write(row_number, 1, item.extension_name, black_url_format)
                    ext.write_string(row_number, 2, item.extension_id, black_url_format)
                    ext.write_string(row_number, 3, item.key, black_field_format)
                    ext.write_string(row_number, 4, item.value, black_value_format)
                    ext.write(row_number, 5, item.interpretation, black_value_format)
                    ext.write(row_number, 6, item.profile, black_value_format)
                    ext.write(row_number, 7, item.source_path, black_value_format)
                    ext.write(row_number, 8, item.offset, black_value_format)
                    ext.write_number(row_number, 9, item.seq, black_value_format)
                    ext.write_string(row_number, 10, item.state, black_value_format)
                    ext.write(row_number, 11, item.was_compressed, black_flag_format)

            except Exception as e:
                log.error(f'Failed to write row to XLSX: {e}')

            row_number += 1

        # Formatting
        ext.freeze_panes(2, 0)  # Freeze top row
        ext.autofilter(1, 0, row_number, 12)  # Add autofilter

        #########################################
        # Sync Data worksheet
        #########################################
        sync_ws = workbook.add_worksheet('Sync Data')
        used_sheet_names.add('sync data')
        # Title bar
        sync_ws.merge_range('A1:E1', f'Hindsight Internet History Forensics (v{__version__}) - Sync Data', title_header_format)
        sync_ws.merge_range('F1:J1', 'Backing LevelDB Specific', center_header_format)

        # Write column headers
        sync_ws.write(1, 0, 'Type', header_format)
        sync_ws.write(1, 1, 'Key', header_format)
        sync_ws.write(1, 2, 'Value', header_format)
        sync_ws.write(1, 3, 'Interpretation', header_format)
        sync_ws.write(1, 4, 'Profile', header_format)
        sync_ws.write(1, 5, 'Source Path', header_format)
        sync_ws.write(1, 6, 'Offset', header_format)
        sync_ws.write(1, 7, 'Sequence', header_format)
        sync_ws.write(1, 8, 'State', header_format)
        sync_ws.write(1, 9, 'File Type', header_format)

        # Set column widths
        sync_ws.set_column('A:A', 20)  # Type
        sync_ws.set_column('B:B', 60)  # Key
        sync_ws.set_column('C:C', 70)  # Value
        sync_ws.set_column('D:D', 40)  # Interpretation
        sync_ws.set_column('E:E', 50)  # Profile
        sync_ws.set_column('F:F', 50)  # Source Path
        sync_ws.set_column('G:G', 12)  # Offset
        sync_ws.set_column('H:H', 8)   # Seq
        sync_ws.set_column('I:I', 8)   # State
        sync_ws.set_column('J:J', 12)  # File Type

        # Start at the row after the headers, and begin writing out the items in parsed_sync_data
        row_number = 2
        for item in self.parsed_sync_data:
            try:
                if item.row_type:
                    sync_ws.write_string(row_number, 0, item.row_type, black_type_format)
                    sync_ws.write_string(row_number, 1, item.key, black_field_format)
                    sync_ws.write_string(row_number, 2, item.value, black_value_format)
                    sync_ws.write(row_number, 3, item.interpretation, black_value_format)
                    sync_ws.write(row_number, 4, item.profile, black_value_format)
                    sync_ws.write(row_number, 5, item.source_path, black_value_format)
                    sync_ws.write(row_number, 6, item.offset, black_value_format)
                    sync_ws.write_number(row_number, 7, item.seq, black_value_format)
                    sync_ws.write_string(row_number, 8, item.state, black_value_format)
                    sync_ws.write_string(row_number, 9, item.file_type, black_value_format)

            except Exception as e:
                log.error(f'Failed to write row to XLSX: {e}')

            row_number += 1

        # Formatting
        sync_ws.freeze_panes(2, 0)  # Freeze top row
        sync_ws.autofilter(1, 0, row_number, 9)  # Add autofilter

        for item in self.__dict__:
            try:
                if self.__dict__[item]['presentation'] and self.__dict__[item]['data']:
                    d = self.__dict__[item]
                    sheet_name = get_unique_sheet_name(d['presentation']['title'])
                    p = workbook.add_worksheet(sheet_name)
                    title = d['presentation']['title']
                    if 'version' in d['presentation']:
                        title += f" (v{d['presentation']['version']})"
                    p.merge_range(0, 0, 0, len(d['presentation']['columns']) - 1,
                                  f"Hindsight Internet History Forensics (v{__version__}) - {title}",
                                  title_header_format)
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

            except Exception as e:
                pass

        # TODO: combine this with above function
        for item in self.__dict__.get('preferences'):
            try:
                if item['presentation'] and item['data']:
                    d = item
                    sheet_name = get_unique_sheet_name(d['presentation']['title'])
                    p = workbook.add_worksheet(sheet_name)
                    title = d['presentation']['title']
                    if 'version' in d['presentation']:
                        title += f" (v{d['presentation']['version']})"
                    p.merge_range(0, 0, 0, len(d['presentation']['columns']) - 1,
                                  f"Hindsight Internet History Forensics (v{__version__}) - {title}",
                                  title_header_format)
                    for counter, column in enumerate(d['presentation']['columns']):
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

            except Exception as e:
                log.warning(f"Exception occurred while writing Preferences page: {e}")

        #########################################
        # Session Reconstruction worksheet
        #########################################
        if hasattr(self, 'session_structures') and self.session_structures:
            WINDOW_SHOW_STATES = {1: 'Normal', 2: 'Minimized', 3: 'Maximized', 5: 'Fullscreen'}
            WINDOW_TYPES = {0: 'Normal', 1: 'App', 2: 'App Popup', 3: 'DevTools'}

            try:
                sess_ws = workbook.add_worksheet(get_unique_sheet_name('Sessions'))

                # Title bar
                sess_ws.merge_range('A1:I1', f'Hindsight Internet History Forensics (v{__version__})'
                                    ' - Sessions', title_header_format)

                # Column headers
                sess_ws.write(1, 0, 'Window', header_format)
                sess_ws.write(1, 1, 'Tab Index', header_format)
                sess_ws.write(1, 2, 'Tab ID', header_format)
                sess_ws.write(1, 3, 'Nav Index', header_format)
                sess_ws.write(1, 4, 'URL', header_format)
                sess_ws.write(1, 5, 'Title', header_format)
                sess_ws.write(1, 6, 'Properties', header_format)
                sess_ws.write(1, 7, 'Tab Group', header_format)
                sess_ws.write(1, 8, 'Profile', header_format)

                # Column widths
                sess_ws.set_column('A:A', 4)   # Window (merged headers; data column is empty)
                sess_ws.set_column('B:B', 10)  # Tab Index
                sess_ws.set_column('C:C', 12)  # Tab ID
                sess_ws.set_column('D:D', 10)  # Nav Index
                sess_ws.set_column('E:E', 70)  # URL
                sess_ws.set_column('F:F', 40)  # Title
                sess_ws.set_column('G:G', 30)  # Properties
                sess_ws.set_column('H:H', 20)  # Tab Group
                sess_ws.set_column('I:I', 30)  # Profile

                window_header_format = workbook.add_format({
                    'font_color': 'white', 'bg_color': '#595959', 'bold': True})
                selected_tab_format = workbook.add_format({
                    'font_color': 'black', 'bg_color': '#E7E6E6', 'bold': True})
                selected_tab_num_format = workbook.add_format({
                    'font_color': 'black', 'bg_color': '#E7E6E6', 'bold': True, 'align': 'right'})
                pinned_format = workbook.add_format({
                    'font_color': '#595959', 'italic': True})
                pinned_num_format = workbook.add_format({
                    'font_color': '#595959', 'italic': True, 'align': 'right'})
                tab_num_format = workbook.add_format({'align': 'right'})
                nav_history_format = workbook.add_format({
                    'font_color': 'gray', 'indent': 2})
                nav_history_num_format = workbook.add_format({
                    'font_color': 'gray', 'align': 'right'})
                nav_current_format = workbook.add_format({
                    'font_color': 'black', 'indent': 2, 'bold': True})
                nav_current_num_format = workbook.add_format({
                    'font_color': 'black', 'bold': True, 'align': 'right'})

                row_number = 2
                for session in self.session_structures:
                    windows = session.get('windows', {})
                    tabs = session.get('tabs', {})
                    tab_groups = session.get('tab_groups', {})
                    active_window = session.get('active_window')
                    tab_current_urls = session.get('tab_current_urls', {})
                    tab_nav_stacks = session.get('tab_nav_stacks', {})
                    profile = session.get('profile', '')

                    # Sort windows: active first, then by ID
                    sorted_windows = sorted(windows.items(),
                                            key=lambda x: (x[0] != active_window, x[0]))

                    for window_id, win in sorted_windows:
                        # Window header row
                        win_type = win.get('type', '?')
                        win_state = win.get('show_state', '?')
                        win_bounds = win.get('bounds', '')
                        active_str = ' [Active]' if window_id == active_window else ''
                        app_name = f' - {win["app_name"]}' if win.get('app_name') else ''
                        window_desc = f'Window {window_id}: {win_type}{app_name} | {win_state} | {win_bounds}{active_str}'

                        sess_ws.merge_range(row_number, 0, row_number, 8, window_desc, window_header_format)
                        row_number += 1

                        # Get tabs in this window, sorted by index
                        window_tabs = [(tid, t) for tid, t in tabs.items() if t.get('window_id') == window_id]
                        window_tabs.sort(key=lambda x: x[1].get('index', 999))
                        selected_tab_index = win.get('selected_tab_index')

                        for tab_id, tab in window_tabs:
                            tab_index = tab.get('index', '')
                            is_selected = tab_index == selected_tab_index
                            is_pinned = tab.get('pinned', False)
                            fmt = selected_tab_format if is_selected else (pinned_format if is_pinned else black_type_format)
                            num_fmt = (selected_tab_num_format if is_selected
                                       else (pinned_num_format if is_pinned else tab_num_format))

                            # Get the current URL for this tab
                            url, title = tab_current_urls.get(tab_id, ('', ''))
                            sel_nav = tab.get('selected_nav_index', '')

                            # Properties
                            props = []
                            if is_selected:
                                props.append('Selected')
                            if is_pinned:
                                props.append('Pinned')
                            if tab.get('extension_app_id'):
                                props.append(f'Ext: {tab["extension_app_id"]}')
                            if tab.get('user_agent_override'):
                                props.append('UA Override')
                            props_str = ', '.join(props)

                            # Tab group
                            group_str = ''
                            gt = tab.get('group_token')
                            if gt and gt in tab_groups:
                                group_str = tab_groups[gt].get('title', '')

                            # Write the tab's current page row
                            sess_ws.write(row_number, 0, '', fmt)
                            sess_ws.write(row_number, 1, tab_index, num_fmt)
                            sess_ws.write(row_number, 2, tab_id, num_fmt)
                            sess_ws.write(row_number, 3, sel_nav, num_fmt)
                            sess_ws.write_string(row_number, 4, url[:500] if url else '', fmt)
                            sess_ws.write_string(row_number, 5, title[:200] if title else '', fmt)
                            sess_ws.write_string(row_number, 6, props_str, fmt)
                            sess_ws.write_string(row_number, 7, group_str, fmt)
                            sess_ws.write_string(row_number, 8, profile, fmt)
                            row_number += 1

                            # Write back/forward navigation stack as sub-rows
                            nav_stack = tab_nav_stacks.get(tab_id, {})
                            if len(nav_stack) > 1:
                                for nav_idx in sorted(nav_stack.keys()):
                                    nav_url, nav_title, _ = nav_stack[nav_idx]
                                    is_current = (nav_idx == sel_nav)
                                    nav_fmt = nav_current_format if is_current else nav_history_format
                                    nav_num_fmt = nav_current_num_format if is_current else nav_history_num_format
                                    current_marker = '<< current' if is_current else ''
                                    sess_ws.write(row_number, 3, nav_idx, nav_num_fmt)
                                    sess_ws.write_string(row_number, 4, nav_url[:500] if nav_url else '', nav_fmt)
                                    sess_ws.write_string(row_number, 5, nav_title[:200] if nav_title else '', nav_fmt)
                                    sess_ws.write_string(row_number, 6, current_marker, nav_fmt)
                                    row_number += 1

                        row_number += 1  # blank row between windows

                # Formatting
                sess_ws.freeze_panes(2, 0)

            except Exception as e:
                log.warning(f"Exception occurred while writing Sessions page: {e}")

        workbook.close()

    def generate_sqlite(self, output_file_path='.temp_db'):

        output_db = sqlite3.connect(output_file_path)
        output_db.text_factory = lambda x: str(x, 'utf-8', 'ignore')

        with output_db:
            c = output_db.cursor()
            c.execute(
                'CREATE TABLE timeline(type TEXT, timestamp TEXT, url TEXT, title TEXT, value TEXT, '
                'interpretation TEXT, profile TEXT, source_item TEXT, visit_source TEXT, '
                'visit_id INT, from_visit INT, opener_visit INT, '
                'visit_duration TEXT, visit_count INT, typed_count INT, url_hidden INT, transition TEXT, '
                'interrupt_reason TEXT, danger_type TEXT, opened INT, etag TEXT, last_modified TEXT, http_headers TEXT)')

            c.execute(
                'CREATE TABLE storage(type TEXT, origin TEXT, key TEXT, value TEXT, '
                'modification_time TEXT, interpretation TEXT, profile TEXT, source_path TEXT, '
                'database TEXT, seq INT, state INT, state_friendly TEXT, file_exists BOOL, file_size INT, '
                'magic_results TEXT)')

            c.execute(
                'CREATE TABLE installed_extensions(name TEXT, description TEXT, version TEXT, ext_id TEXT, '
                'profile TEXT, permissions TEXT, manifest TEXT)')

            c.execute(
                'CREATE TABLE extension_data(type TEXT, name TEXT, extension_id TEXT, key TEXT, value TEXT, '
                'interpretation TEXT, profile TEXT, source_path TEXT, offset INT, seq INT, state INT, '
                'state_friendly TEXT, was_compressed BOOL)')

            c.execute(
                'CREATE TABLE sync_data(type TEXT, key TEXT, value TEXT, interpretation TEXT, profile TEXT, '
                'source_path TEXT, offset INT, seq INT, state INT, state_friendly TEXT, file_type TEXT)')

            c.execute(
                'CREATE TABLE preferences(group_name TEXT, name TEXT, value TEXT, description TEXT, title TEXT)')

            def state_to_int(state_value):
                if state_value is None:
                    return None
                return 0 if state_value == 'Deleted' else 1

            def preference_field(pref_item, field_name):
                if isinstance(pref_item, dict):
                    return pref_item.get(field_name)
                return getattr(pref_item, field_name, None)

            def is_empty(value):
                return value is None or value == ''

            for item in self.parsed_artifacts:
                if item.row_type.startswith('url'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, interpretation, profile, source_item, '
                        'visit_source, visit_id, from_visit, opener_visit, visit_duration, visit_count, typed_count, '
                        'url_hidden, transition) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.interpretation,
                         item.profile, item.source_item, item.visit_source, item.visit_id, item.from_visit,
                         item.opener_visit, item.visit_duration, item.visit_count, item.typed_count, item.hidden,
                         item.transition_friendly))

                elif item.row_type.startswith('media'):
                    if item.source_title:
                        media_message = f'Watched{item.watch_time} on {item.source_title} '\
                                        f'(ending at {item.position}/{item.media_duration}) '\
                                        f'[has_video: {item.has_video}; has_audio: {item.has_audio}]'
                    else:
                        media_message = f'Watched{item.watch_time} '\
                                        f'[has_video: {item.has_video}; has_audio: {item.has_audio}]'
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.title,
                         media_message, item.interpretation, item.profile, item.source_item))

                elif item.row_type.startswith('autofill'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.name, item.value, item.interpretation,
                         item.profile, item.source_item))

                elif item.row_type.startswith('download'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item, '
                        'interrupt_reason, danger_type, opened, etag, last_modified) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.status_friendly, item.value,
                         item.interpretation, item.profile, item.source_item, item.interrupt_reason_friendly,
                         item.danger_type_friendly, item.opened, item.etag, item.last_modified))

                elif item.row_type.startswith('bookmark folder'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.name, item.value,
                         item.interpretation, item.profile, item.source_item))

                elif item.row_type.startswith('bookmark'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                         item.interpretation, item.profile, item.source_item))

                elif item.row_type.startswith('cookie'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                         item.interpretation, item.profile, item.source_item))

                elif item.row_type.startswith('local storage'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                         item.interpretation, item.profile, item.source_item))

                elif item.row_type.startswith('cache'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item, '
                        'etag, last_modified, http_headers)'
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.data_summary,
                         item.locations, item.interpretation, item.profile, item.source_item,
                         item.etag, item.last_modified, item.http_headers_str))

                elif item.row_type.startswith('login'):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                         item.interpretation, item.profile, item.source_item))

                elif item.row_type.startswith(('preference', 'site setting', 'notification', 'session', 'permission action', 'profile creation')):
                    c.execute(
                        'INSERT INTO timeline (type, timestamp, url, title, value, interpretation, profile, source_item) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                         item.interpretation, item.profile, item.source_item))

            for item in self.parsed_storage:
                if item.row_type.startswith('local'):
                    c.execute(
                        'INSERT INTO storage (type, origin, key, value, modification_time, '
                        'interpretation, profile, source_path, seq, state, state_friendly) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, item.origin, item.key, item.value, item.last_modified,
                         item.interpretation, item.profile, item.source_path, item.seq,
                         state_to_int(item.state), item.state))

                elif item.row_type.startswith('session'):
                    c.execute(
                        'INSERT INTO storage (type, origin, key, value, '
                        'interpretation, profile, source_path, seq, state, state_friendly) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, item.origin, item.key, item.value, item.interpretation, item.profile,
                         item.source_path, item.seq, state_to_int(item.state), item.state))

                elif item.row_type.startswith('file system'):
                    c.execute(
                        'INSERT INTO storage (type, origin, key, value, modification_time, '
                        'interpretation, profile, source_path, seq, state, state_friendly, file_exists, file_size, '
                        'magic_results) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, item.origin, item.key, item.value, item.last_modified,
                         item.interpretation, item.profile, item.source_path, item.seq,
                         state_to_int(item.state), item.state,
                         item.file_exists, item.file_size, item.magic_results))

                elif item.row_type.startswith('indexed'):
                    c.execute(
                        'INSERT INTO storage (type, origin, key, value, '
                        'interpretation, profile, source_path, seq, state, state_friendly, database) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, item.origin, item.key, item.value, item.interpretation, item.profile,
                         item.source_path, item.seq, state_to_int(item.state), item.state, item.database))

            for item in self.parsed_extension_data:
                if item.row_type:
                    c.execute(
                        'INSERT INTO extension_data (type, name, extension_id, key, value, '
                        'interpretation, profile, source_path, offset, seq, state, state_friendly, was_compressed) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, item.extension_name, item.extension_id, item.key, item.value,
                         item.interpretation, item.profile, item.source_path, item.offset, item.seq,
                         state_to_int(item.state), item.state, item.was_compressed))

            for item in self.parsed_sync_data:
                if item.row_type:
                    c.execute(
                        'INSERT INTO sync_data (type, key, value, interpretation, profile, source_path, '
                        'offset, seq, state, state_friendly, file_type) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (item.row_type, item.key, item.value, item.interpretation, item.profile, item.source_path,
                         item.offset, item.seq, state_to_int(item.state), item.state, item.file_type))

            if self.__dict__.get('installed_extensions'):
                for extension in self.installed_extensions['data']:
                    c.execute(
                        'INSERT INTO installed_extensions (name, description, version, ext_id, profile, '
                        'permissions, manifest) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (extension.name, extension.description, extension.version, extension.ext_id,
                         extension.profile, extension.permissions, extension.manifest))

            for preference_group in self.preferences:
                title = preference_group.get('presentation', {}).get('title')
                current_group = None
                for preference in preference_group.get('data', []):
                    group_value = preference_field(preference, 'group')
                    name_value = preference_field(preference, 'name')
                    value_value = preference_field(preference, 'value')
                    description_value = preference_field(preference, 'description')

                    if group_value and is_empty(name_value) and is_empty(value_value) and is_empty(description_value):
                        current_group = group_value
                        continue

                    if group_value:
                        current_group = group_value
                    elif current_group:
                        group_value = current_group

                    c.execute(
                        'INSERT INTO preferences (group_name, name, value, description, title) '
                        'VALUES (?, ?, ?, ?, ?)',
                        (group_value, name_value, value_value, description_value, title))

        output_db.close()

    def generate_jsonl(self, output_file):
        with open(output_file, mode='w') as jsonl:
            unparsed_count = 0

            def write_jsonl_record(record):
                nonlocal unparsed_count
                record_json = json.dumps(record, cls=HindsightEncoder)
                if record_json == 'null':
                    unparsed_count += 1
                    return
                jsonl.write(record_json)
                jsonl.write('\n')

            for parsed_artifact in self.parsed_artifacts:
                write_jsonl_record(parsed_artifact)
            for parsed_storage in self.parsed_storage:
                write_jsonl_record(parsed_storage)
            for parsed_extension_data in self.parsed_extension_data:
                write_jsonl_record(parsed_extension_data)
            for parsed_sync_data in self.parsed_sync_data:
                write_jsonl_record(parsed_sync_data)
            for preference_group in self.preferences:
                current_group = None
                for preference in preference_group.get('data', []):
                    group_value = preference.get('group')
                    name_value = preference.get('name')
                    value_value = preference.get('value')
                    description_value = preference.get('description')

                    is_header_row = (
                        group_value and
                        name_value is None and
                        value_value is None and
                        description_value is None
                    )
                    if is_header_row:
                        current_group = group_value
                        continue

                    if group_value:
                        current_group = group_value
                    elif current_group:
                        group_value = current_group

                    preference_record = {
                        'source_short': 'WEBHIST',
                        'source_long': 'Chrome Preferences',
                        'parser': f'hindsight/{__version__}',
                        'timestamp_desc': 'Not a time',
                        'data_type': 'chrome:preferences:entry',
                        'datetime': '1970-01-01T00:00:00.000000+00:00',
                        'group': group_value,
                        'name': name_value,
                        'value': value_value,
                        'description': description_value,
                        'message': f'{name_value or ""}: {value_value or ""}',
                    }
                    preference_record = {k: v for k, v in preference_record.items() if v is not None}
                    write_jsonl_record(preference_record)
            installed_extensions = getattr(self, 'installed_extensions', None)
            if installed_extensions and installed_extensions.get('data'):
                for extension in installed_extensions['data']:
                    write_jsonl_record(extension)
            if unparsed_count:
                log.warning(f'Skipped {unparsed_count} unparsed JSONL record(s)')
