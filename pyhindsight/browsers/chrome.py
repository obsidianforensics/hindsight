# -*- coding: utf-8 -*-
import sqlite3
import os
import sys
import datetime
import re
import struct
import json
import codecs
import logging
import shutil
from pyhindsight.browsers.webbrowser import WebBrowser
from pyhindsight.utils import friendly_date, to_datetime

# Try to import optionally modules - do nothing on failure, as status is tracked elsewhere
try:
    import win32crypt
except ImportError:
    pass

try:
    import keyring
except ImportError:
    pass

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
except ImportError:
    pass


class Chrome(WebBrowser):
    def __init__(self, profile_path, browser_name=None, cache_path=None, version=None, timezone=None,
                 parsed_artifacts=None, storage=None, installed_extensions=None, artifacts_counts=None, artifacts_display=None,
                 available_decrypts=None):
        # TODO: try to fix this to use super()
        WebBrowser.__init__(self, profile_path, browser_name=browser_name, cache_path=cache_path, version=version,
                            timezone=timezone, parsed_artifacts=parsed_artifacts, artifacts_counts=artifacts_counts,
                            artifacts_display=artifacts_display)
        self.profile_path = profile_path
        self.browser_name = "Chrome"
        self.cache_path = cache_path
        self.timezone = timezone
        self.installed_extensions = installed_extensions
        self.cached_key = None
        self.available_decrypts = available_decrypts
        self.storage = storage

        if self.version is None:
            self.version = []

        if self.structure is None:
            self.structure = {}

        if self.parsed_artifacts is None:
            self.parsed_artifacts = []

        if self.installed_extensions is None:
            self.installed_extensions = []

        if self.artifacts_counts is None:
            self.artifacts_counts = {}

        if self.artifacts_display is None:
            self.artifacts_display = {}

        if self.available_decrypts is None:
            self.available_decrypts = {'windows': 0, 'mac': 0, 'linux': 0}

        if self.available_decrypts['windows'] == 1:
            import win32crypt

        if self.available_decrypts['mac'] == 1:
            import keyring
            from Cryptodome.Cipher import AES
            from Cryptodome.Protocol.KDF import PBKDF2

        if self.available_decrypts['linux'] == 1:
            from Cryptodome.Cipher import AES
            from Cryptodome.Protocol.KDF import PBKDF2

    def determine_version(self):
        """Determine version of Chrome databases files by looking for combinations of columns in certain tables.

        Based on research I did to create "The Evolution of Chrome Databases Reference Chart"
        (http://www.obsidianforensics.com/blog/evolution-of-chrome-databases-chart/)
        """
        possible_versions = range(1, 61)

        def trim_lesser_versions_if(column, table, version):
            """Remove version numbers < 'version' from 'possible_versions' if 'column' isn't in 'table', and keep
            versions >= 'version' if 'column' is in 'table'.
            """
            if table:
                if column in table:
                    possible_versions[:] = [x for x in possible_versions if x >= version]
                else:
                    possible_versions[:] = [x for x in possible_versions if x < version]

        def trim_greater_versions_if(column, table, version):
            """Remove version numbers > 'version' from 'possible_versions' if 'column' isn't in 'table', and keep
            versions =< 'version' if 'column' is in 'table'.
            """
            if table:
                if column in table:
                    possible_versions[:] = [x for x in possible_versions if x <= version]
                else:
                    possible_versions[:] = [x for x in possible_versions if x > version]

        def trim_lesser_versions(version):
            """Remove version numbers < 'version' from 'possible_versions'"""
            possible_versions[:] = [x for x in possible_versions if x >= version]

        if 'History' in self.structure.keys():
            if 'visits' in self.structure['History'].keys():
                trim_lesser_versions_if('visit_duration', self.structure['History']['visits'], 20)
            if 'visit_source' in self.structure['History'].keys():
                trim_lesser_versions_if('source', self.structure['History']['visit_source'], 7)
            if 'downloads' in self.structure['History'].keys():
                trim_lesser_versions_if('target_path', self.structure['History']['downloads'], 26)
                trim_lesser_versions_if('opened', self.structure['History']['downloads'], 16)
                trim_lesser_versions_if('etag', self.structure['History']['downloads'], 30)
                trim_lesser_versions_if('original_mime_type', self.structure['History']['downloads'], 37)
                trim_lesser_versions_if('last_access_time', self.structure['History']['downloads'], 59)
            if 'downloads_slices' in self.structure['History'].keys():
                trim_lesser_versions(58)

        # the pseudo-History file generated by the ChromeNative Volatility plugin should use the v30 query
        elif (db.startswith('History__') for db in self.structure.keys()):
            trim_lesser_versions(30)

        if 'Cookies' in self.structure.keys():
            if 'cookies' in self.structure['Cookies'].keys():
                trim_lesser_versions_if('persistent', self.structure['Cookies']['cookies'], 17)
                trim_lesser_versions_if('priority', self.structure['Cookies']['cookies'], 28)
                trim_lesser_versions_if('encrypted_value', self.structure['Cookies']['cookies'], 33)
                trim_lesser_versions_if('firstpartyonly', self.structure['Cookies']['cookies'], 44)

        if 'Web Data' in self.structure.keys():
            if 'autofill' in self.structure['Web Data'].keys():
                trim_lesser_versions_if('name', self.structure['Web Data']['autofill'], 2)
                trim_lesser_versions_if('date_created', self.structure['Web Data']['autofill'], 35)
            if 'autofill_profiles' in self.structure['Web Data'].keys():
                trim_lesser_versions_if('language_code', self.structure['Web Data']['autofill_profiles'], 36)
            if 'autofill_sync_metadata' in self.structure['Web Data'].keys():
                trim_lesser_versions(57)
            if 'web_apps' not in self.structure['Web Data'].keys():
                trim_lesser_versions(38)
            if 'credit_cards' in self.structure['Web Data'].keys():
                trim_lesser_versions_if('billing_address_id', self.structure['Web Data']['credit_cards'], 53)

        if 'Login Data' in self.structure.keys():
            if 'logins' in self.structure['Login Data'].keys():
                trim_lesser_versions_if('display_name', self.structure['Login Data']['logins'], 39)
                trim_lesser_versions_if('generation_upload_status', self.structure['Login Data']['logins'], 42)
                trim_greater_versions_if('ssl_valid', self.structure['Login Data']['logins'], 53)
                trim_lesser_versions_if('possible_username_pairs', self.structure['Login Data']['logins'], 59)

        if 'Network Action Predictor' in self.structure.keys():
            if 'resource_prefetch_predictor_url' in self.structure['Network Action Predictor'].keys():
                trim_lesser_versions(22)
                trim_lesser_versions_if('key', self.structure['Network Action Predictor']['resource_prefetch_predictor_url'], 55)
                trim_lesser_versions_if('proto', self.structure['Network Action Predictor']['resource_prefetch_predictor_url'], 54)

        self.version = possible_versions

    def get_history(self, path, history_file, version, row_type):
        # Set up empty return array
        results = []

        logging.info("History items from {}:".format(history_file))

        # TODO: visit_source table?  don't have good sample data
        # TODO: visits where visit_count = 0; means it should be in Archived History but could be helpful to have if
        # that file is missing.  Changing the first JOIN to a LEFT JOIN adds these in.

        # Queries for different versions
        query = {59: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                             urls.hidden, visits.visit_time, visits.from_visit, visits.visit_duration,
                             visits.transition, visit_source.source
                          FROM urls JOIN visits ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 30: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                             urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.visit_duration,
                             visits.transition, visit_source.source
                          FROM urls JOIN visits ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 29: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                             urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.visit_duration,
                             visits.transition, visit_source.source, visits.is_indexed
                          FROM urls JOIN visits ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 20: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                             urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.visit_duration,
                             visits.transition, visit_source.source, visits.is_indexed
                          FROM urls JOIN visits ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 7:  '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                             urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.transition,
                             visit_source.source
                          FROM urls JOIN visits ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 1:  '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                             urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.transition
                          FROM urls, visits WHERE urls.id = visits.url'''}

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            logging.info(" - Using SQL query for History items for Chrome v{}".format(compatible_version))
            try:
                # Connect to 'History' sqlite db
                history_path = os.path.join(path, history_file)
                db_file = sqlite3.connect(history_path)
                logging.info(" - Reading from file '{}'".format(history_path))

                # Use a dictionary cursor
                db_file.row_factory = WebBrowser.dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                try:
                    cursor.execute(query[compatible_version])
                except Exception as e:
                    logging.error(" - Error querying '{}': {}".format(history_path, e))
                    self.artifacts_counts[history_file] = 'Failed'
                    return

                for row in cursor:
                    duration = None
                    if row.get('visit_duration'):
                        duration = datetime.timedelta(microseconds=row.get('visit_duration'))

                    new_row = Chrome.URLItem(row.get('id'), row.get('url'), row.get('title'),
                                             to_datetime(row.get('visit_time'), self.timezone),
                                             to_datetime(row.get('last_visit_time'), self.timezone), row.get('visit_count'),
                                             row.get('typed_count'), row.get('from_visit'), row.get('transition'),
                                             row.get('hidden'), row.get('favicon_id'), row.get('is_indexed'),
                                             unicode(duration), row.get('source'))

                    # Set the row type as determined earlier
                    new_row.row_type = row_type

                    # Translate the transition value to human-readable
                    new_row.decode_transition()

                    # Translate the numeric visit_source.source code to human-readable
                    new_row.decode_source()

                    # Add the new row to the results array
                    results.append(new_row)

                db_file.close()
                self.artifacts_counts[history_file] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except IOError:
                self.artifacts_counts[history_file] = 'Failed'
                logging.error(" - Couldn't open {}".format(os.path.join(path, history_file)))

    def get_downloads(self, path, database, version, row_type):
        # Set up empty return array
        results = []

        logging.info("Download items from {}:".format(database))

        # Queries for different versions
        query = {30: '''SELECT downloads.id, downloads_url_chains.url, downloads.received_bytes, downloads.total_bytes,
                            downloads.state, downloads.target_path, downloads.start_time, downloads.end_time,
                            downloads.opened, downloads.danger_type, downloads.interrupt_reason, downloads.etag,
                            downloads.last_modified, downloads_url_chains.chain_index
                        FROM downloads, downloads_url_chains WHERE downloads_url_chains.id = downloads.id''',
                 26: '''SELECT downloads.id, downloads_url_chains.url, downloads.received_bytes, downloads.total_bytes,
                            downloads.state, downloads.target_path, downloads.start_time, downloads.end_time,
                            downloads.opened, downloads.danger_type, downloads.interrupt_reason,
                            downloads_url_chains.chain_index
                        FROM downloads, downloads_url_chains WHERE downloads_url_chains.id = downloads.id''',
                 16: '''SELECT downloads.id, downloads.url, downloads.received_bytes, downloads.total_bytes,
                            downloads.state, downloads.full_path, downloads.start_time, downloads.end_time,
                            downloads.opened
                        FROM downloads''',
                 1:  '''SELECT downloads.id, downloads.url, downloads.received_bytes, downloads.total_bytes,
                            downloads.state, downloads.full_path, downloads.start_time
                        FROM downloads'''}

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            logging.info(" - Using SQL query for Download items for Chrome v{}".format(compatible_version))
            try:
                # Connect to 'History' sqlite db
                history_path = os.path.join(path, database)
                db_file = sqlite3.connect(history_path)
                logging.info(" - Reading from file '{}'".format(history_path))

                # Use a dictionary cursor
                db_file.row_factory = WebBrowser.dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                try:
                    cursor.execute(query[compatible_version])
                except Exception as e:
                    logging.error(" - Error querying '{}': {}".format(history_path, e))
                    self.artifacts_counts[database + '_downloads'] = 'Failed'
                    return

                for row in cursor:
                    try:
                        # TODO: collapse download chain into one entry per download
                        # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                        new_row = Chrome.DownloadItem(row.get('id'), row.get('url'), row.get('received_bytes'),
                                               row.get('total_bytes'), row.get('state'), row.get('full_path'),
                                               to_datetime(row.get('start_time'), self.timezone),
                                               to_datetime(row.get('end_time'), self.timezone), row.get('target_path'),
                                               row.get('current_path'), row.get('opened'), row.get('danger_type'),
                                               row.get('interrupt_reason'), row.get('etag'), row.get('last_modified'),
                                               row.get('chain_index'))
                    except:
                        logging.exception(" - Exception processing record; skipped.")

                    new_row.decode_interrupt_reason()
                    new_row.decode_danger_type()
                    new_row.decode_download_state()
                    new_row.timestamp = new_row.start_time

                    new_row.create_friendly_status()

                    if new_row.full_path is not None:
                        new_row.value = new_row.full_path
                    elif new_row.current_path is not None:
                        new_row.value = new_row.current_path
                    elif new_row.target_path is not None:
                        new_row.value = new_row.target_path
                    else:
                        new_row.value = u'Error retrieving download location'
                        logging.error(" - Error retrieving download location for download '{}'".format(new_row.url))

                    new_row.row_type = row_type
                    results.append(new_row)

                db_file.close()
                self.artifacts_counts[database + '_downloads'] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except IOError:
                self.artifacts_counts[database + '_downloads'] = 'Failed'
                logging.error(" - Couldn't open {}".format(os.path.join(path, database)))

    def decrypt_cookie(self, encrypted_value):
        """Decryption based on work by Nathan Henrie and Jordan Wright as well as Chromium source:
         - Mac/Linux: http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
         - Windows: https://gist.github.com/jordan-wright/5770442#file-chrome_extract-py
         - Relevant Chromium source code: http://src.chromium.org/viewvc/chrome/trunk/src/components/os_crypt/
         """
        salt = b'saltysalt'
        iv = b' ' * 16
        length = 16

        def chrome_decrypt(encrypted, key=None):
            # Encrypted cookies should be prefixed with 'v10' according to the
            # Chromium code. Strip it off.
            encrypted = encrypted[3:]

            # Strip padding by taking off number indicated by padding
            # eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.
            def clean(x):
                return x[:-ord(x[-1])]

            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            decrypted = cipher.decrypt(encrypted)

            return clean(decrypted)

        decrypted_value = "<error>"
        if encrypted_value is not None:
            if len(encrypted_value) >= 2:
                # If running Chrome on Windows
                if sys.platform == 'win32' and self.available_decrypts['windows'] is 1:
                    try:
                        decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
                    except:
                        decrypted_value = "<encrypted>"
                # If running Chrome on OSX
                elif sys.platform == 'darwin' and self.available_decrypts['mac'] is 1:
                    try:
                        if not self.cached_key:
                            my_pass = keyring.get_password('Chrome Safe Storage', 'Chrome')
                            my_pass = my_pass.encode('utf8')
                            iterations = 1003
                            self.cached_key = PBKDF2(my_pass, salt, length, iterations)
                        decrypted_value = chrome_decrypt(encrypted_value, key=self.cached_key)
                    except:
                        pass
                else:
                    decrypted_value = "<encrypted>"

                # If running Chromium on Linux.
                # Unlike Win/Mac, we can decrypt Linux cookies without the user's pw
                if decrypted_value is "<encrypted>" and self.available_decrypts['linux'] is 1:
                    try:
                        if not self.cached_key:
                            my_pass = 'peanuts'.encode('utf8')
                            iterations = 1
                            self.cached_key = PBKDF2(my_pass, salt, length, iterations)
                        decrypted_value = chrome_decrypt(encrypted_value, key=self.cached_key)
                    except:
                        pass

        return decrypted_value

    def get_cookies(self, path, database, version):
        # Set up empty return array
        results = []

        logging.info("Cookie items from {}:".format(database))

        # Queries for different versions
        query = {33: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly,
                            cookies.persistent, cookies.has_expires, cookies.priority, cookies.encrypted_value
                        FROM cookies''',
                 28: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly,
                            cookies.persistent, cookies.has_expires, cookies.priority
                        FROM cookies''',
                 17: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly,
                            cookies.persistent, cookies.has_expires
                        FROM cookies''',
                 1:  '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly
                        FROM cookies'''}

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            logging.info(" - Using SQL query for Cookie items for Chrome v{}".format(compatible_version))
            try:
                # Connect to 'Cookies' sqlite db
                db_path = os.path.join(path, database)
                db_file = sqlite3.connect(db_path)
                logging.info(" - Reading from file '{}'".format(db_path))

                # Use a dictionary cursor
                db_file.row_factory = WebBrowser.dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    if row.get('encrypted_value') is not None:
                        if len(row.get('encrypted_value')) >= 2:
                            cookie_value = self.decrypt_cookie(row.get('encrypted_value')).decode('utf-8')
                        else:
                            cookie_value = row.get('value')
                    else:
                        cookie_value = row.get('value')
                        # print type(cookie_value), cookie_value

                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    new_row = Chrome.CookieItem(row.get('host_key'), row.get('path'), row.get('name'), cookie_value,
                                                to_datetime(row.get('creation_utc'), self.timezone),
                                                to_datetime(row.get('last_access_utc'), self.timezone),
                                                to_datetime(row.get('expires_utc'), self.timezone), row.get('secure'),
                                                row.get('httponly'), row.get('persistent'),
                                                row.get('has_expires'), row.get('priority'))

                    accessed_row = Chrome.CookieItem(row.get('host_key'), row.get('path'), row.get('name'), cookie_value,
                                                     to_datetime(row.get('creation_utc'), self.timezone),
                                                     to_datetime(row.get('last_access_utc'), self.timezone),
                                                     to_datetime(row.get('expires_utc'), self.timezone), row.get('secure'),
                                                     row.get('httponly'), row.get('persistent'),
                                                     row.get('has_expires'), row.get('priority'))

                    new_row.url = (new_row.host_key + new_row.path)
                    accessed_row.url = (accessed_row.host_key + accessed_row.path)

                    # Create the row for when the cookie was created
                    new_row.row_type = u'cookie (created)'
                    new_row.timestamp = new_row.creation_utc
                    results.append(new_row)

                    # If the cookie was created and accessed at the same time (only used once), or if the last accessed
                    # time is 0 (happens on iOS), don't create an accessed row
                    if new_row.creation_utc != new_row.last_access_utc and accessed_row.last_access_utc != to_datetime(0, self.timezone):
                        accessed_row.row_type = u'cookie (accessed)'
                        accessed_row.timestamp = accessed_row.last_access_utc
                        results.append(accessed_row)

                db_file.close()
                self.artifacts_counts[database] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except Exception, e:
                self.artifacts_counts[database] = 'Failed - {}'.format(e)
                logging.error(" - Couldn't open {}".format(os.path.join(path, database)))

    def get_login_data(self, path, database, version):
        # Set up empty return array
        results = []

        logging.info("Password items from {}:".format(database))

        # Queries for different versions
        query = {29:  '''SELECT origin_url, action_url, username_element, username_value, password_element,
                            password_value, date_created, blacklisted_by_user, times_used FROM logins''',
                 6:  '''SELECT origin_url, action_url, username_element, username_value, password_element,
                            password_value, date_created, blacklisted_by_user FROM logins'''}

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            logging.info(" - Using SQL query for Password items for Chrome v{}".format(compatible_version))
            try:
                # Connect to 'Login Data' sqlite db
                db_path = os.path.join(path, database)
                db_file = sqlite3.connect(db_path)
                logging.info(" - Reading from file '{}'".format(db_path))

                # Use a dictionary cursor
                db_file.row_factory = WebBrowser.dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                # print 'cursor ',cursor.fetchall()

                for row in cursor:
                    if row.get('blacklisted_by_user') == 1:
                        blacklist_row = Chrome.LoginItem(to_datetime(row.get('date_created'), self.timezone),
                                                         url=row.get('action_url'), name=row.get('username_element').decode(),
                                                         value=u'<User chose to "Never save password" for this site>',
                                                         count=row.get('times_used'))
                        blacklist_row.row_type = u'login (blacklist)'
                        results.append(blacklist_row)

                    if row.get('username_value') is not None and row.get('blacklisted_by_user') == 0:
                        username_row = Chrome.LoginItem(to_datetime(row.get('date_created'), self.timezone),
                                                        url=row.get('action_url'), name=row.get('username_element'),
                                                        value=row.get('username_value'), count=row.get('times_used'))
                        username_row.row_type = u'login (username)'
                        results.append(username_row)

                    if row.get('password_value') is not None and row.get('blacklisted_by_user') == 0:
                        password = None
                        try:
                            # Windows is all I've had time to test; Ubuntu uses built-in password manager
                            password = win32crypt.CryptUnprotectData(row.get('password_value').decode(), None, None, None, 0)[1]
                        except:
                            password = self.decrypt_cookie(row.get('password_value'))

                        password_row = Chrome.LoginItem(to_datetime(row.get('date_created'), self.timezone),
                                                        url=row.get('action_url'), name=row.get('password_element'),
                                                        value=password, count=row.get('times_used'))
                        password_row.row_type = u'login (password)'
                        results.append(password_row)

                db_file.close()
                self.artifacts_counts['Login Data'] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except Exception as e:
                self.artifacts_counts['Login Data'] = 'Failed'
                logging.error(" - Couldn't open {}: {}".format(os.path.join(path, database), e))

    def get_autofill(self, path, database, version):
        # Set up empty return array
        results = []

        logging.info("Autofill items from {}:".format(database))

        # Queries for different versions
        query = {35: '''SELECT autofill.date_created, autofill.date_last_used, autofill.name, autofill.value,
                        autofill.count FROM autofill''',
                 2: '''SELECT autofill_dates.date_created, autofill.name, autofill.value, autofill.count
                        FROM autofill, autofill_dates WHERE autofill.pair_id = autofill_dates.pair_id'''}

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            logging.info(" - Using SQL query for Autofill items for Chrome v{}".format(compatible_version))
            try:
                # Connect to 'Web Data' SQLite db
                db_path = os.path.join(path, database)
                db_file = sqlite3.connect(db_path)
                logging.info(" - Reading from file '{}'".format(db_path))

                # Use a dictionary cursor
                db_file.row_factory = WebBrowser.dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    results.append(Chrome.AutofillItem(to_datetime(row.get('date_created'), self.timezone), row.get('name'),
                                                row.get('value'), row.get('count')))

                    if row.get('date_last_used') and row.get('count') > 1:
                        results.append(Chrome.AutofillItem(to_datetime(row.get('date_last_used'), self.timezone),
                                                    row.get('name'), row.get('value'), row.get('count')))

                db_file.close()
                self.artifacts_counts['Autofill'] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except Exception as e:
                self.artifacts_counts['Autofill'] = 'Failed'
                logging.error(" - Couldn't open {}: {}".format(os.path.join(path, database), e))

    def get_bookmarks(self, path, file, version):
        # Set up empty return array
        results = []

        logging.info("Bookmark items from {}:".format(file))

        # Connect to 'Bookmarks' JSON file
        bookmarks_path = os.path.join(path, file)

        try:
            bookmarks_file = codecs.open(bookmarks_path, 'rb', encoding='utf-8')
            decoded_json = json.loads(bookmarks_file.read())
            logging.info(" - Reading from file '{}'".format(bookmarks_path))
        except:
            logging.error(" - Error opening '{}'".format(bookmarks_path))
            self.artifacts_counts['Bookmarks'] = 'Failed'
            return

        # TODO: sync_id
        def process_bookmark_children(parent, children):
            for child in children:
                if child["type"] == "url":
                    results.append(Chrome.BookmarkItem(to_datetime(child["date_added"], self.timezone),
                                                child["name"], child["url"], parent))
                elif child["type"] == "folder":
                    new_parent = parent + " > " + child["name"]
                    results.append(Chrome.BookmarkFolderItem(to_datetime(child["date_added"], self.timezone),
                                                      child["date_modified"], child["name"], parent))
                    process_bookmark_children(new_parent, child["children"])

        for top_level_folder in decoded_json["roots"].keys():
            if top_level_folder != "sync_transaction_version" and top_level_folder != "synced" and top_level_folder != "meta_info":
                if decoded_json["roots"][top_level_folder]["children"] is not None:
                    process_bookmark_children(decoded_json["roots"][top_level_folder]["name"],
                                              decoded_json["roots"][top_level_folder]["children"])

        bookmarks_file.close()
        self.artifacts_counts['Bookmarks'] = len(results)
        logging.info(" - Parsed {} items".format(len(results)))
        self.parsed_artifacts.extend(results)

    def get_local_storage(self, path, dir_name):
        results = []
        illegal_xml_re = re.compile(ur'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]',
                                    re.UNICODE)

        # Grab file list of 'Local Storage' directory
        ls_path = os.path.join(path, dir_name)
        logging.info("Local Storage:")
        logging.info(" - Reading from {}".format(ls_path))

        local_storage_listing = os.listdir(ls_path)
        logging.debug(" - {} files in Local Storage directory"
                      .format(len(local_storage_listing)))
        filtered_listing = []

        for ls_file in local_storage_listing:
            if (ls_file[:3] == 'ftp' or ls_file[:4] == 'http' or ls_file[:4] == 'file' or
                    ls_file[:16] == 'chrome-extension') and ls_file[-8:] != '-journal':
                filtered_listing.append(ls_file)
                ls_file_path = os.path.join(ls_path, ls_file)
                ls_created = os.stat(ls_file_path).st_ctime

                def to_unicode(raw_data):
                    if type(raw_data) in (int, long, float):
                        return unicode(raw_data, 'utf-16', errors='replace')
                    elif type(raw_data) is unicode:
                        return raw_data
                    elif type(raw_data) is buffer:
                        try:
                            # When Javascript uses localStorage, it saves everything in UTF-16
                            uni = unicode(raw_data, 'utf-16', errors='replace')
                            # However, some websites use custom compression to squeeze more data in, and just pretend
                            # it's UTF-16, which can result in "characters" that are illegal in XML. We need to remove
                            # these so Excel will be able to display the output.
                            # TODO: complete work on decoding the compressed data
                            return illegal_xml_re.sub(u'\ufffd', uni)

                        except UnicodeDecodeError:
                            return u'<buffer decode error>'
                    else:
                        return u'<unknown type decode error>'

                # Connect to Local Storage file sqlite db
                try:
                    db_file = sqlite3.connect(ls_file_path)
                except Exception as e:
                    logging.warning(" - Error opening {}: {}".format(ls_file_path, e))
                    break

                # Use a dictionary cursor
                db_file.row_factory = WebBrowser.dict_factory
                cursor = db_file.cursor()

                try:
                    cursor.execute('SELECT key,value FROM ItemTable')
                    for row in cursor:
                        # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                        results.append(Chrome.LocalStorageItem(ls_file.decode(), to_datetime(ls_created, self.timezone),
                                                        row.get('key'), to_unicode(row.get('value'))))
                except Exception as e:
                    logging.warning(" - Error reading key/values from {}: {}".format(ls_file_path, e))
                    pass

        self.artifacts_counts['Local Storage'] = len(results)
        logging.info(" - Parsed {} items from {} files".format(len(results), len(filtered_listing)))
        self.parsed_artifacts.extend(results)

    def get_extensions(self, path, dir_name):
        results = []
        logging.info("Extensions:")

        # Grab listing of 'Extensions' directory
        ext_path = os.path.join(path, dir_name)
        logging.info(" - Reading from {}".format(ext_path))
        ext_listing = os.listdir(ext_path)
        logging.debug(" - {count} files in Extensions directory: {list}".format(list=str(ext_listing),
                                                                                count=len(ext_listing)))

        # Only process directories with the expected naming convention
        app_id_re = re.compile(r'^([a-z]{32})$')
        ext_listing = [x for x in ext_listing if app_id_re.match(x)]
        logging.debug(" - {count} files in Extensions directory will be processed: {list}".format(
            list=str(ext_listing), count=len(ext_listing)))

        # Process each directory with an app_id name
        for app_id in ext_listing:
            # Get listing of the contents of app_id directory; should contain subdirs for each version of the extension.
            ext_vers_listing = os.path.join(ext_path, app_id)
            ext_vers = os.listdir(ext_vers_listing)

            # Connect to manifest.json in latest version directory
            manifest_path = os.path.join(ext_vers_listing, ext_vers[-1], 'manifest.json')
            try:
                manifest_file = codecs.open(manifest_path, 'rb', encoding='utf-8', errors='replace')
            except IOError:
                logging.error(" - Error opening {} for extension {}".format(manifest_path, app_id))
                break

            name = None
            description = None

            if manifest_file:
                try:
                    decoded_manifest = json.loads(manifest_file.read())
                    if decoded_manifest["name"][:2] == '__':
                        if decoded_manifest["default_locale"]:
                            locale_messages_path = os.path.join(ext_vers_listing, ext_vers[-1], '_locales',
                                                                decoded_manifest["default_locale"], 'messages.json')
                            locale_messages_file = codecs.open(locale_messages_path, 'rb', encoding='utf-8',
                                                               errors='replace')
                            decoded_locale_messages = json.loads(locale_messages_file.read())
                            try:
                                name = decoded_locale_messages[decoded_manifest["name"][6:-2]]["message"]
                            except KeyError:
                                try:
                                    name = decoded_locale_messages[decoded_manifest["name"][6:-2]].lower["message"]
                                except KeyError:
                                    try:
                                        # Google Wallet / Chrome Payments is weird/hidden - name is saved different than other extensions
                                        name = decoded_locale_messages["app_name"]["message"]
                                    except:
                                        logging.warning(" - Error reading 'name' for {}".format(app_id))
                                        name = "<error>"
                    else:
                        try:
                            name = decoded_manifest["name"]
                        except KeyError:
                            name = None
                            logging.error(" - Error reading 'name' for {}".format(app_id))

                    if "description" in decoded_manifest.keys():
                        if decoded_manifest["description"][:2] == '__':
                            if decoded_manifest["default_locale"]:
                                locale_messages_path = os.path.join(ext_vers_listing, ext_vers[-1], '_locales',
                                                                    decoded_manifest["default_locale"], 'messages.json')
                                locale_messages_file = codecs.open(locale_messages_path, 'rb', encoding='utf-8',
                                                                   errors='replace')
                                decoded_locale_messages = json.loads(locale_messages_file.read())
                                try:
                                    description = decoded_locale_messages[decoded_manifest["description"][6:-2]]["message"]
                                except KeyError:
                                    try:
                                        description = decoded_locale_messages[decoded_manifest["description"][6:-2]].lower["message"]
                                    except KeyError:
                                        try:
                                            # Google Wallet / Chrome Payments is weird/hidden - name is saved different than other extensions
                                            description = decoded_locale_messages["app_description"]["message"]
                                        except:
                                            description = "<error>"
                                            logging.error(" - Error reading 'message' for {}".format(app_id))
                        else:
                            try:
                                description = decoded_manifest["description"]
                            except KeyError:
                                description = None
                                logging.warning(" - Error reading 'description' for {}".format(app_id))

                    results.append(Chrome.BrowserExtension(app_id, name, description, decoded_manifest["version"]))
                except:
                    logging.error(" - Error decoding manifest file for {}".format(app_id))
                    pass

        self.artifacts_counts['Extensions'] = len(results)
        logging.info(" - Parsed {} items".format(len(results)))
        presentation = {'title': 'Installed Extensions',
                        'columns': [
                            {'display_name': 'Extension Name',
                             'data_name': 'name',
                             'display_width': 26},
                            {'display_name': 'Description',
                             'data_name': 'description',
                             'display_width': 60},
                            {'display_name': 'Version',
                             'data_name': 'version',
                             'display_width': 10},
                            {'display_name': 'App ID',
                             'data_name': 'app_id',
                             'display_width': 36}
                        ]}
        self.installed_extensions = {'data': results, 'presentation': presentation}

    def get_preferences(self, path, preferences_file):
        def check_and_append_pref(parent, pref, value=None, description=None):
            # If the preference exists, continue
            if parent.get(pref):
                # If no value is specified, use the value from the preference JSON
                if not value:
                    value = parent[pref]
                # Append the preference dict to our results array
                results.append({
                    'group': None,
                    'name': pref,
                    'value': value,
                    'description': description})
            else:
                results.append({
                    'group': None,
                    'name': pref,
                    'value': '<not present>',
                    'description': description})

        def check_and_append_pref_and_children(parent, pref, value=None, description=None):
            # If the preference exists, continue
            if parent.get(pref):
                # If no value is specified, use the value from the preference JSON
                if not value:
                    value = parent[pref]
                # Append the preference dict to our results array
                results.append({
                    'group': None,
                    'name': pref,
                    'value': value,
                    'description': description})
            else:
                results.append({
                    'group': None,
                    'name': pref,
                    'value': '<not present>',
                    'description': description})

        def append_group(group, description=None):
            # Append the preference group to our results array
            results.append({
                'group': group,
                'name': None,
                'value': None,
                'description': description})

        def append_pref(pref, value=None, description=None):
            results.append({
                'group': None,
                'name': pref,
                'value': value,
                'description': description})

        results = []
        logging.info("Preferences:")
        prefs = None

        # Open 'Preferences' file
        pref_path = os.path.join(path, preferences_file)
        try:
            logging.info(" - Reading from {}".format(pref_path))
            pref_file = codecs.open(pref_path, 'rb', encoding='utf-8', errors='replace')
            prefs = json.loads(pref_file.read())
        except:
            logging.error(" - Error decoding Preferences file {}".format(pref_path))
            self.artifacts_counts[preferences_file] = 'Failed'
            return

        if prefs:
            # Account Information
            if prefs.get('account_info'):
                append_group("Account Information")
                for account in prefs['account_info']:
                    append_pref('account_id: {}'.format(account['account_id']), 'email: {}'.format(account['email']))

            # Local file paths
            append_group("Local file paths")
            if prefs.get('download'):
                check_and_append_pref(prefs['download'], 'default_directory')
            if prefs.get('printing'):
                if prefs.get('print_preview_sticky_settings'):
                    check_and_append_pref(prefs['printing']['print_preview_sticky_settings'], 'savePath')
            if prefs.get('savefile'):
                check_and_append_pref(prefs['savefile'], 'default_directory')
            if prefs.get('selectfile'):
                check_and_append_pref(prefs['selectfile'], 'last_directory')

            # Autofill
            if prefs.get('autofill'):
                append_group("Autofill")
                check_and_append_pref(prefs['autofill'], 'enabled')

            # Clearing Chrome Data
            if prefs.get('browser'):
                append_group("Clearing Chrome Data")
                if prefs['browser'].get('last_clear_browsing_data_time'):
                    check_and_append_pref(prefs['browser'], 'last_clear_browsing_data_time',
                                          friendly_date(prefs['browser']['last_clear_browsing_data_time']),
                                          "Last time the history was cleared")
                check_and_append_pref(prefs['browser'], 'clear_lso_data_enabled')
                if prefs['browser'].get('clear_data'):
                    check_and_append_pref(prefs['browser']['clear_data'], 'time_period',
                                          description="0: past hour; 1: past day; 2: past week; 3: last 4 weeks; "
                                                      "4: the beginning of time")
                    check_and_append_pref(prefs['browser']['clear_data'], 'content_licenses')
                    check_and_append_pref(prefs['browser']['clear_data'], 'hosted_apps_data')
                    check_and_append_pref(prefs['browser']['clear_data'], 'cookies')
                    check_and_append_pref(prefs['browser']['clear_data'], 'download_history')
                    check_and_append_pref(prefs['browser']['clear_data'], 'passwords')
                    check_and_append_pref(prefs['browser']['clear_data'], 'form_data')

            append_group("Per Host Zoom Levels", "These settings persist even when the history is cleared, and may be "
                                                 "useful in some cases.")
            # There are per_host_zoom_levels keys in two locations: profile.per_host_zoom_levels and
            # partition.per_host_zoom_levels.[integer].
            if prefs.get('profile'):
                if prefs['profile'].get('per_host_zoom_levels'):
                    for zoom in prefs['profile']['per_host_zoom_levels'].keys():
                        check_and_append_pref(prefs['profile']['per_host_zoom_levels'], zoom)

            if prefs.get('partition'):
                if prefs['partition'].get('per_host_zoom_levels'):
                    for number in prefs['partition']['per_host_zoom_levels'].keys():
                        for zoom in prefs['partition']['per_host_zoom_levels'][number].keys():
                            check_and_append_pref(prefs['partition']['per_host_zoom_levels'][number], zoom)

            if prefs.get('profile'):
                if prefs['profile'].get('content_settings'):
                    if prefs['profile']['content_settings'].get('pattern_pairs'):
                        append_group("Profile Content Settings", "These settings persist even when the history is "
                                                                 "cleared, and may be useful in some cases.")
                        for pair in prefs['profile']['content_settings']['pattern_pairs'].keys():
                            # Adding the space before the domain prevents Excel from freaking out...  idk.
                            append_pref(' '+str(pair), str(prefs['profile']['content_settings']['pattern_pairs'][pair]))

        self.artifacts_counts[preferences_file] = len(results)
        logging.info(" - Parsed {} items".format(len(results)))
        presentation = {'title': 'Preferences',
                        'columns': [
                            {'display_name': 'Group',
                             'data_name': 'group',
                             'display_width': 8},
                            {'display_name': 'Setting Name',
                             'data_name': 'name',
                             'display_width': 40},
                            {'display_name': 'Value',
                             'data_name': 'value',
                             'display_width': 35},
                            {'display_name': 'Description',
                             'data_name': 'description',
                             'display_width': 60},
                            ]}

        self.preferences = {'data': results, 'presentation': presentation}

    def get_cache(self, path, dir_name, row_type=None):
        """
        read the index file to walk whole cache // from cacheParse.py

        Reads the whole cache and store the collected data in a table
        or find out if the given list of urls is in the cache. If yes it
        return a list of the corresponding entries.
        """

        # Set up empty return array
        results = []

        path = os.path.join(path, dir_name)
        logging.info("Cache items from {}:".format(path))

        try:
            logging.debug(" - Found cache index file")
            cacheBlock = CacheBlock(os.path.join(path, 'index'))

            # Checking type
            if cacheBlock.type != CacheBlock.INDEX:
                logging.error(" - 'index' block file is invalid (has wrong magic type)")
                self.artifacts_counts[dir_name] = 'Failed'
                return
            logging.debug(" - Parsed index block file (version {})".format(cacheBlock.version))
        except:
            logging.error(" - Failed to parse index block file")

        try:
            index = open(os.path.join(path, 'index'), 'rb')
        except:
            logging.error(" - Error reading cache index file {}".format(os.path.join(path, 'index')))
            self.artifacts_counts[dir_name] = 'Failed'
            return

        # Skipping Header
        index.seek(92 * 4)

        for key in range(cacheBlock.tableSize):
            raw = struct.unpack('I', index.read(4))[0]
            if raw != 0:
                try:
                    entry = CacheEntry(CacheAddress(raw, path=path), row_type, self.timezone)
                    # Add the new row to the results array
                    results.append(entry)
                except Exception, e:
                    logging.error(" - Error parsing cache entry {}: {}".format(raw, str(e)))

                try:
                    # Checking if there is a next item in the bucket because
                    # such entries are not stored in the Index File so they will
                    # be ignored during iterative lookup in the hash table
                    while entry.next != 0:
                        entry = CacheEntry(CacheAddress(entry.next, path=path), row_type, self.timezone)
                        results.append(entry)
                except Exception, e:
                    logging.error(" - Error parsing cache entry {}: {}".format(entry.next, str(e)))

        self.artifacts_counts[dir_name] = len(results)
        logging.info(" - Parsed {} items".format(len(results)))
        self.parsed_artifacts.extend(results)

    def get_application_cache(self, path, dir_name, row_type=None):
        """
        read the index file to walk whole cache // from cacheParse.py

        Reads the whole cache and store the collected data in a table
        or find out if the given list of urls is in the cache. If yes it
        return a list of the corresponding entries.
        """

        # Set up empty return array
        results = []

        base_path = os.path.join(path, dir_name)
        cache_path = os.path.join(base_path, 'Cache')
        logging.info("Application Cache items from {}:".format(path))

        # Connect to 'Index' sqlite db
        db_path = os.path.join(base_path, 'Index')
        try:
            index_db = sqlite3.connect(db_path)
            logging.info(" - Reading from file '{}'".format(db_path))

            # Use a dictionary cursor
            index_db.row_factory = WebBrowser.dict_factory
            cursor = index_db.cursor()
        except:
            logging.error(" - Error opening Application Cache Index SQLite DB {}".format(db_path))
            self.artifacts_counts[dir_name] = 'Failed'
            return

        try:
            cache_block = CacheBlock(os.path.join(cache_path, 'index'))
            # Checking type
            if cache_block.type != CacheBlock.INDEX:
                raise Exception("Invalid Index File")

            index = open(os.path.join(cache_path, 'index'), 'rb')
        except:
            logging.error(" - Error reading cache index file {}".format(os.path.join(path, 'index')))
            self.artifacts_counts[dir_name] = 'Failed'
            return

        # Skipping Header
        index.seek(92 * 4)

        for key in range(cache_block.tableSize):
            raw = struct.unpack('I', index.read(4))[0]
            if raw != 0:
                try:
                    entry = CacheEntry(CacheAddress(raw, path=cache_path), row_type, self.timezone)
                    cursor.execute('''SELECT url from Entries WHERE response_id=?''', [entry.key])
                    index_url = cursor.fetchone()
                    if index_url:
                        entry.url = index_url['url']

                    # Add the new row to the results array
                    results.append(entry)

                    # Checking if there is a next item in the bucket because
                    # such entries are not stored in the Index File so they will
                    # be ignored during iterative lookup in the hash table
                    while entry.next != 0:
                        entry = CacheEntry(CacheAddress(entry.next, path=cache_path), row_type, self.timezone)
                        cursor.execute('''SELECT url FROM Entries WHERE response_id=?''', [entry.key])
                        index_url = cursor.fetchone()
                        if index_url:
                            entry.url = index_url['url']
                        results.append(entry)
                except Exception, e:
                    logging.error(" - Error parsing cache entry {}: {}".format(raw, str(e)))

        index_db.close()

        self.artifacts_counts[dir_name] = len(results)
        logging.info(" - Parsed {} items".format(len(results)))
        self.parsed_artifacts.extend(results)

    def get_fs_path_leveldb(self, lvl_db_path):
        import leveldb
        db = leveldb.LevelDB(lvl_db_path, create_if_missing=False)
        nodes = {}
        pairs = list(db.RangeIter())
        for pair in pairs:
            # Each origin value should be a tuple of length 2; if not, log it and skip it.
            if not isinstance(pair, tuple) or len(pair) is not 2:
                logging.warning(" - Found LevelDB key/value pair that is not formed as expected ({}); skipping.".format(str(pair)))
                continue
            fs_path_re = re.compile(b"\x00(?P<dir>\d\d)(\\\\|/)(?P<id>\d{8})\x00")
            m = fs_path_re.search(pair[1])
            if m:
                nodes[pair[0]] = {"dir": m.group("dir"), "id": m.group("id")}
        return nodes

    def get_prefixed_leveldb_pairs(self, lvl_db_path, prefix=""):
        """Given a path to a LevelDB and a prefix string, return all pairs starting"""
        import leveldb
        db = leveldb.LevelDB(lvl_db_path, create_if_missing=False)
        cleaned_pairs = []
        pairs = list(db.RangeIter())
        for pair in pairs:
            # Each origin value should be a tuple of length 2; if not, log it and skip it.
            if not isinstance(pair, tuple) or len(pair) is not 2:
                logging.warning(" - Found LevelDB key/value pair that is not formed as expected ({}); skipping.".format(str(pair)))
                continue
            if pair[0].startswith(prefix):
                # Split the tuple in the origin domain and origin ID, and remove the prefix from the domain
                (key, value) = pair
                key = key[len(prefix):]
                cleaned_pairs.append({"key": key, "value": value})

        return cleaned_pairs

    def build_logical_fs_path(self, node, parent_path=None):
        if not parent_path:
            parent_path = []

        parent_path.append(node["name"])
        node["path"] = parent_path
        for child_node in node["children"].itervalues():
            self.build_logical_fs_path(child_node, parent_path=list(node["path"]))

    def flatten_nodes_to_list(self, output_list, node):
        output_row = {
            "type": node["type"],
            "display_type": node["display_type"],
            "origin": node["path"][0],
            "logical_path": "\\".join(node["path"][1:]),
            "local_path": "File System\\{}\\{}".format(node["origin_id"], node["type"])
        }
        if node.get("fs_path"):
            output_row["local_path"] += "\\{}\\{}".format(node["fs_path"]["dir"], node["fs_path"]["id"])

        output_list.append(output_row)
        for child_node in node["children"].itervalues():
            self.flatten_nodes_to_list(output_list, child_node)

    def get_file_system(self, path, dir_name):
        try:
            import leveldb
        except ImportError:
            self.artifacts_counts['File System'] = 0
            logging.info("File System: Failed to parse; couldn't import leveldb.")
            return

        results = {}
        result_list = []
        result_count = 0
        logging.info("File System:")

        # Grab listing of 'File System' directory
        fs_root_path = os.path.join(path, dir_name)
        logging.info(" - Reading from {}".format(fs_root_path))
        fs_root_listing = os.listdir(fs_root_path)
        logging.debug(" - {count} files in File System directory: {list}".format(list=str(fs_root_listing),
                                                                                 count=len(fs_root_listing)))
        # 'Origins' is a LevelDB that holds the mapping for each of the [000, 001, 002, ... ] dirs to web origin (https_www.google.com_0)
        if 'Origins' in fs_root_listing:
            lvl_db_path = os.path.join(fs_root_path, 'Origins')
            origins = self.get_prefixed_leveldb_pairs(lvl_db_path, "ORIGIN:")
            for origin in origins:
                origin_domain = origin["key"]
                origin_id = origin["value"]
                origin_root_path = os.path.join(fs_root_path, origin_id)
                t_tree = {}
                p_tree = {}

                if os.path.isdir(origin_root_path):
                    origin_t_path = os.path.join(origin_root_path, 't')
                    if os.path.isdir(origin_t_path):
                        logging.debug(" - Found 'temporary' data directory for origin {}".format(origin_domain))
                        origin_t_paths_path = os.path.join(origin_t_path, 'Paths')
                        if os.path.isdir(origin_t_paths_path):
                            try:
                                t_items = self.get_prefixed_leveldb_pairs(origin_t_paths_path, "CHILD_OF:")
                                t_fs_paths = self.get_fs_path_leveldb(origin_t_paths_path)
                                t_nodes = {"0": {"name": origin_domain, "type": "t", "display_type": "file system (temporary)",
                                                 "origin_id": origin_id, "fs_path": t_fs_paths.get('0'), "children": {}}}
                                for item in t_items:
                                    (parent, name) = item["key"].split(":")
                                    t_nodes[item["value"]] = {"name": name, "type": "t", "display_type": "file system (temporary)",
                                                              "origin_id": origin_id, "parent": parent, "fs_path": t_fs_paths.get(item["value"]),
                                                              "children": {}}
                                    result_count += 1

                                for id in t_nodes:
                                    if t_nodes[id].get("parent"):
                                        t_nodes[t_nodes[id].get("parent")]["children"][id] = t_nodes[id]
                                    else:
                                        t_tree[id] = t_nodes[id]

                                self.build_logical_fs_path(t_tree["0"])
                                self.flatten_nodes_to_list(result_list, t_tree["0"])
                            except Exception as e:
                                logging.error(" - Error accessing LevelDB {}: {}".format(origin_t_paths_path, str(e)))

                    origin_p_path = os.path.join(origin_root_path, 'p')
                    if os.path.isdir(origin_p_path):
                        logging.debug(" - Found 'persistent' data directory for origin {}".format(origin_domain))
                        origin_p_paths_path = os.path.join(origin_p_path, 'Paths')
                        if os.path.isdir(origin_p_paths_path):
                            try:
                                p_items = self.get_prefixed_leveldb_pairs(origin_p_paths_path, "CHILD_OF:")
                                p_fs_paths = self.get_fs_path_leveldb(origin_p_paths_path)
                                p_nodes = {"0": {"name": origin_domain, "type": "p", "display_type": "file system (persistent)",
                                                 "origin_id": origin_id, "fs_path": p_fs_paths.get('0'), "children": {}}}
                                for item in p_items:
                                    (parent, name) = item["key"].split(":")
                                    p_nodes[item["value"]] = {"name": name, "type": "p", "display_type": "file system (persistent)",
                                                              "origin_id": origin_id, "parent": parent, "fs_path": p_fs_paths.get(item["value"]),
                                                              "children": {}}
                                    result_count += 1

                                for id in p_nodes:
                                    if p_nodes[id].get("parent"):
                                        p_nodes[p_nodes[id].get("parent")]["children"][id] = p_nodes[id]
                                    else:
                                        p_tree[id] = p_nodes[id]

                                self.build_logical_fs_path(p_tree["0"])
                                self.flatten_nodes_to_list(result_list, p_tree["0"])
                            except Exception as e:
                                logging.error(" - Error accessing LevelDB {}: {}".format(origin_p_paths_path, str(e)))

        logging.info(" - Parsed {} items".format(len(result_list)))
        self.artifacts_counts['File System'] = len(result_list)

        presentation = {'title': 'Storage',
                        'columns': [
                            {'display_name': 'Storage Type',
                             'data_name': 'display_type',
                             'display_width': 26},
                            {'display_name': 'Origin',
                             'data_name': 'origin',
                             'display_width': 50},
                            {'display_name': 'Logical Path / Key',
                             'data_name': 'logical_path',
                             'display_width': 50},
                            {'display_name': 'Local Path',
                             'data_name': 'local_path',
                             'display_width': 36}
                        ]}
        self.storage = {'data': result_list, 'presentation': presentation}

    def process(self):
        supported_databases = ['History', 'Archived History', 'Web Data', 'Cookies', 'Login Data', 'Extension Cookies']
        supported_subdirs = ['Local Storage', 'Extensions', 'File System']
        supported_jsons = ['Bookmarks']  # , 'Preferences']
        supported_items = supported_databases + supported_subdirs + supported_jsons
        logging.debug("Supported items: " + str(supported_items))

        input_listing = os.listdir(self.profile_path)
        for input_file in input_listing:
            # If input_file is in our supported db list, or if the input_file name starts with a
            # value in supported_databases followed by '__' (used to add in dbs from additional sources)
            if input_file in supported_databases or input_file.startswith(tuple([db + '__' for db in supported_databases])):
                # Process structure from Chrome database files
                self.build_structure(self.profile_path, input_file)

        # Use the structure of the input files to determine possible Chrome versions
        self.determine_version()

        if len(self.version) > 1:
            self.display_version = "%s-%s" % (self.version[0], self.version[-1])
        else:
            self.display_version = self.version[0]

        print self.format_processing_output("Detected {} version".format(self.browser_name), self.display_version)

        logging.info("Detected {} version {}".format(self.browser_name, self.display_version))

        logging.info("Found the following supported files or directories:")
        for input_file in input_listing:
            if input_file in supported_items:
                logging.info(" - %s" % input_file)

        # Process History files
        custom_type_re = re.compile(r'__([A-z0-9\._]*)$')
        for input_file in input_listing:
            if re.search(r'^History__|^History$', input_file):
                row_type = u'url'
                custom_type_m = re.search(custom_type_re, input_file)
                if custom_type_m:
                    row_type = u'url ({})'.format(custom_type_m.group(1))
                self.get_history(self.profile_path, input_file, self.version, row_type)
                display_type = 'URL' if not custom_type_m else 'URL ({})'.format(custom_type_m.group(1))
                self.artifacts_display[input_file] = "{} records".format(display_type)
                print self.format_processing_output(self.artifacts_display[input_file],
                                                    self.artifacts_counts[input_file])

                row_type = u'download'
                if custom_type_m:
                    row_type = u'download ({})'.format(custom_type_m.group(1))
                self.get_downloads(self.profile_path, input_file, self.version, row_type)
                display_type = 'Download' if not custom_type_m else 'Download ({})'.format(custom_type_m.group(1))
                self.artifacts_display[input_file + '_downloads'] = "{} records".format(display_type)
                print self.format_processing_output(self.artifacts_display[input_file + '_downloads'],
                                                    self.artifacts_counts[input_file + '_downloads'])

        if 'Archived History' in input_listing:
            self.get_history(self.profile_path, 'Archived History', self.version, u'url (archived)')
            self.artifacts_display['Archived History'] = "Archived URL records"
            print self.format_processing_output(self.artifacts_display['Archived History'],
                                                self.artifacts_counts['Archived History'])

        if self.cache_path is not None and self.cache_path != '':
            c_path, c_dir = os.path.split(self.cache_path)
            self.get_cache(c_path, c_dir, row_type=u'cache')
            self.artifacts_display['Cache'] = "Cache records"
            print self.format_processing_output(self.artifacts_display['Cache'],
                                                self.artifacts_counts['Cache'])

        elif 'Cache' in input_listing:
            self.get_cache(self.profile_path, 'Cache', row_type=u'cache')
            self.artifacts_display['Cache'] = "Cache records"
            print self.format_processing_output(self.artifacts_display['Cache'],
                                                self.artifacts_counts['Cache'])
        if 'GPUCache' in input_listing:
            self.get_cache(self.profile_path, 'GPUCache', row_type=u'cache (gpu)')
            self.artifacts_display['GPUCache'] = "GPU Cache records"
            print self.format_processing_output(self.artifacts_display['GPUCache'],
                                                self.artifacts_counts['GPUCache'])

        if 'Media Cache' in input_listing:
            self.get_cache(self.profile_path, 'Media Cache', row_type=u'cache (media)')
            self.artifacts_display['Media Cache'] = "Media Cache records"
            print self.format_processing_output(self.artifacts_display['Media Cache'],
                                                self.artifacts_counts['Media Cache'])

        if 'Application Cache' in input_listing:
            self.get_application_cache(self.profile_path, 'Application Cache', row_type=u'cache (application)')
            self.artifacts_display['Application Cache'] = "Application Cache records"
            print self.format_processing_output(self.artifacts_display['Application Cache'],
                                                self.artifacts_counts['Application Cache'])

        if 'Cookies' in input_listing:
            self.get_cookies(self.profile_path, 'Cookies', self.version)
            self.artifacts_display['Cookies'] = "Cookie records"
            print self.format_processing_output(self.artifacts_display['Cookies'],
                                                self.artifacts_counts['Cookies'])

        if 'Web Data' in input_listing:
            self.get_autofill(self.profile_path, 'Web Data', self.version)
            self.artifacts_display['Autofill'] = "Autofill records"
            print self.format_processing_output(self.artifacts_display['Autofill'],
                                                self.artifacts_counts['Autofill'])

        if 'Bookmarks' in input_listing:
            self.get_bookmarks(self.profile_path, 'Bookmarks', self.version)
            self.artifacts_display['Bookmarks'] = "Bookmark records"
            print self.format_processing_output(self.artifacts_display['Bookmarks'],
                                                self.artifacts_counts['Bookmarks'])

        if 'Local Storage' in input_listing:
            self.get_local_storage(self.profile_path, 'Local Storage')
            self.artifacts_display['Local Storage'] = "Local Storage records"
            print self.format_processing_output(self.artifacts_display['Local Storage'],
                                                self.artifacts_counts['Local Storage'])

        if 'Extensions' in input_listing:
            self.get_extensions(self.profile_path, 'Extensions')
            self.artifacts_display['Extensions'] = "Extensions"
            print self.format_processing_output(self.artifacts_display['Extensions'],
                                                self.artifacts_counts['Extensions'])

        if 'Extension Cookies' in input_listing:
            self.get_cookies(self.profile_path, 'Extension Cookies', self.version)
            self.artifacts_display['Extension Cookies'] = "Extension Cookie records"
            print self.format_processing_output(self.artifacts_display['Extension Cookies'],
                                                self.artifacts_counts['Extension Cookies'])

        if 'Login Data' in input_listing:
            self.get_login_data(self.profile_path, 'Login Data', self.version)
            self.artifacts_display['Login Data'] = "Login Data records"
            print self.format_processing_output(self.artifacts_display['Login Data'],
                                                self.artifacts_counts['Login Data'])

        if 'Preferences' in input_listing:
            self.get_preferences(self.profile_path, 'Preferences')
            self.artifacts_display['Preferences'] = "Preference Items"
            print self.format_processing_output(self.artifacts_display['Preferences'],
                                                self.artifacts_counts['Preferences'])

        if 'File System' in input_listing:
            self.get_file_system(self.profile_path, 'File System')
            self.artifacts_display['File System'] = "File System Items"
            print self.format_processing_output(self.artifacts_display['File System'],
                                                self.artifacts_counts['File System'])

        # Destroy the cached key so that json serialization doesn't
        # have a cardiac arrest on the non-unicode binary data.
        self.cached_key = None

        self.parsed_artifacts.sort()

    class URLItem(WebBrowser.URLItem):
        def __init__(self, url_id, url, title, visit_time, last_visit_time, visit_count, typed_count, from_visit,
                     transition, hidden, favicon_id, indexed=None, visit_duration=None, visit_source=None,
                     transition_friendly=None):
            WebBrowser.URLItem.__init__(self, url_id=url_id, url=url, title=title, visit_time=visit_time, last_visit_time=last_visit_time,
                                        visit_count=visit_count, typed_count=typed_count, from_visit=from_visit, transition=transition,
                                        hidden=hidden, favicon_id=favicon_id, indexed=indexed, visit_duration=visit_duration,
                                        visit_source=visit_source, transition_friendly=transition_friendly)

        def decode_transition(self):
            # Source: http://src.chromium.org/svn/trunk/src/content/public/common/page_transition_types_list.h
            transition_friendly = {
                0: u'link',                 # User got to this page by clicking a link on another page.
                1: u'typed',                # User got this page by typing the URL in the URL bar.  This should not be
                                            # used for cases where the user selected a choice that didn't look at all
                                            # like a URL; see GENERATED below.
                                            # We also use this for other 'explicit' navigation actions.
                2: u'auto bookmark',        # User got to this page through a suggestion in the UI, for example)
                                            # through the destinations page.
                3: u'auto subframe',        # This is a subframe navigation. This is any content that is automatically
                                            # loaded in a non-toplevel frame. For example, if a page consists of
                                            # several frames containing ads, those ad URLs will have this transition
                                            # type. The user may not even realize the content in these pages is a
                                            # separate frame, so may not care about the URL (see MANUAL below).
                4: u'manual subframe',      # For subframe navigations that are explicitly requested by the user and
                                            # generate new navigation entries in the back/forward list. These are
                                            # probably more important than frames that were automatically loaded in
                                            # the background because the user probably cares about the fact that this
                                            # link was loaded.
                5: u'generated',            # User got to this page by typing in the URL bar and selecting an entry
                                            # that did not look like a URL.  For example, a match might have the URL
                                            # of a Google search result page, but appear like 'Search Google for ...'.
                                            # These are not quite the same as TYPED navigations because the user
                                            # didn't type or see the destination URL.
                                            # See also KEYWORD.
                6: u'start page',           # This is a toplevel navigation. This is any content that is automatically
                                            # loaded in a toplevel frame.  For example, opening a tab to show the ASH
                                            # screen saver, opening the devtools window, opening the NTP after the safe
                                            # browsing warning, opening web-based dialog boxes are examples of
                                            # AUTO_TOPLEVEL navigations.
                7: u'form submit',          # The user filled out values in a form and submitted it. NOTE that in
                                            # some situations submitting a form does not result in this transition
                                            # type. This can happen if the form uses script to submit the contents.
                8: u'reload',               # The user 'reloaded' the page, either by hitting the reload button or by
                                            # hitting enter in the address bar.  NOTE: This is distinct from the
                                            # concept of whether a particular load uses 'reload semantics' (i.e.
                                            # bypasses cached data).  For this reason, lots of code needs to pass
                                            # around the concept of whether a load should be treated as a 'reload'
                                            # separately from their tracking of this transition type, which is mainly
                                            # used for proper scoring for consumers who care about how frequently a
                                            # user typed/visited a particular URL.
                                            # SessionRestore and undo tab close use this transition type too.
                9: u'keyword',              # The url was generated from a replaceable keyword other than the default
                                            # search provider. If the user types a keyword (which also applies to
                                            # tab-to-search) in the omnibox this qualifier is applied to the transition
                                            # type of the generated url. TemplateURLModel then may generate an
                                            # additional visit with a transition type of KEYWORD_GENERATED against the
                                            # url 'http://' + keyword. For example, if you do a tab-to-search against
                                            # wikipedia the generated url has a transition qualifer of KEYWORD, and
                                            # TemplateURLModel generates a visit for 'wikipedia.org' with a transition
                                            # type of KEYWORD_GENERATED.
                10: u'keyword generated'}   # Corresponds to a visit generated for a keyword. See description of
                                            # KEYWORD for more details.

            qualifiers_friendly = {
                0x00800000: u'Blocked',                # A managed user attempted to visit a URL but was blocked.
                0x01000000: u'Forward or Back',        # User used the Forward or Back button to navigate among browsing
                                                       # history.
                0x02000000: u'From Address Bar',       # User used the address bar to trigger this navigation.
                0x04000000: u'Home Page',              # User is navigating to the home page.
                0x08000000: u'From API',               # The transition originated from an external application; the exact
                                                       # definition of this is embedder dependent.
                0x10000000: u'Navigation Chain Start', # The beginning of a navigation chain.
                0x20000000: u'Navigation Chain End',   # The last transition in a redirect chain.
                0x40000000: u'Client Redirect',        # Redirects caused by JavaScript or a meta refresh tag on the page.
                0x80000000: u'Server Redirect'}        # Redirects sent from the server by HTTP headers. It might be nice to
                                                       # break this out into 2 types in the future, permanent or temporary,
                                                       # if we can get that information from WebKit.
            raw = self.transition
            # If the transition has already been translated to a string, just use that
            if isinstance(raw, (str, unicode)):
                self.transition_friendly = raw
                return

            core_mask = 0xff
            code = raw & core_mask

            if code in transition_friendly.keys():
                self.transition_friendly = transition_friendly[code] + '; '

            for qualifier in qualifiers_friendly:
                if raw & qualifier == qualifier:
                    if not self.transition_friendly:
                        self.transition_friendly = u""
                    self.transition_friendly += qualifiers_friendly[qualifier] + '; '

        def decode_source(self):
            # https://code.google.com/p/chromium/codesearch#chromium/src/components/history/core/browser/history_types.h
            source_friendly = {
                0: u'Synced',
                None: u'Local',
                2: u'Added by Extension',
                3: u'Firefox (Imported)',
                4: u'IE (Imported)',
                5: u'Safari (Imported)'}

            raw = self.visit_source

            if raw in source_friendly.keys():
                self.visit_source = source_friendly[raw]

    class DownloadItem(WebBrowser.DownloadItem):
        def __init__(self, download_id, url, received_bytes, total_bytes, state, full_path=None, start_time=None,
                     end_time=None, target_path=None, current_path=None, opened=None, danger_type=None,
                     interrupt_reason=None, etag=None, last_modified=None, chain_index=None, interrupt_reason_friendly=None,
                     danger_type_friendly=None, state_friendly=None, status_friendly=None):
            WebBrowser.DownloadItem.__init__(self, download_id, url, received_bytes, total_bytes, state, full_path=full_path,
                                             start_time=start_time, end_time=end_time, target_path=target_path,
                                             current_path=current_path, opened=opened, danger_type=danger_type,
                                             interrupt_reason=interrupt_reason, etag=etag, last_modified=last_modified,
                                             chain_index=chain_index, interrupt_reason_friendly=interrupt_reason_friendly,
                                             danger_type_friendly=danger_type_friendly, state_friendly=state_friendly,
                                             status_friendly=status_friendly)

        def decode_interrupt_reason(self):
            interrupts = {
                0:  u'No Interrupt',                # Success

                # from download_interrupt_reason_values.h on Chromium site
                # File errors
                1:  u'File Error',                  # Generic file operation failure.
                2:  u'Access Denied',               # The file cannot be accessed due to security restrictions.
                3:  u'Disk Full',                   # There is not enough room on the drive.
                5:  u'Path Too Long',               # The directory or file name is too long.
                6:  u'File Too Large',              # The file is too large for the file system to handle.
                7:  u'Virus',                       # The file contains a virus.
                10: u'Temporary Problem',           # The file was in use. Too many files are opened at once. We have run
                                                    # out of memory.
                11: u'Blocked',                     # The file was blocked due to local policy.
                12: u'Security Check Failed',       # An attempt to check the safety of the download failed due to
                                                    # unexpected reasons. See http://crbug.com/153212.
                13: u'Resume Error',                # An attempt was made to seek past the end of a file in opening a file
                                                    # (as part of resuming a previously interrupted download).

                # Network errors
                20: u'Network Error',               # Generic network failure.
                21: u'Operation Timed Out',         # The network operation timed out.
                22: u'Connection Lost',             # The network connection has been lost.
                23: u'Server Down',                 # The server has gone down.

                # Server responses
                30: u'Server Error',                # The server indicates that the operation has failed (generic).
                31: u'Range Request Error',         # The server does not support range requests. Internal use only:
                                                    # must restart from the beginning.
                32: u'Server Precondition Error',   # The download request does not meet the specified precondition.
                                                    # Internal use only:  the file has changed on the server.
                33: u'Unable to get file',          # The server does not have the requested data.

                # User input
                40: u'Cancelled',                   # The user cancelled the download.
                41: u'Browser Shutdown',            # The user shut down the browser. Internal use only:  resume pending
                                                    # downloads if possible.

                # Crash
                50: u'Browser Crashed'}             # The browser crashed. Internal use only:  resume pending downloads
                                                    # if possible.

            if self.interrupt_reason in interrupts.keys():
                self.interrupt_reason_friendly = interrupts[self.interrupt_reason]
            elif self.interrupt_reason is None:
                self.interrupt_reason_friendly = None
            else:
                self.interrupt_reason_friendly = u'[Error - Unknown Interrupt Code]'
                logging.error(" - Error decoding interrupt code for download '{}'".format(self.url))

        def decode_danger_type(self):
            # from download_danger_type.h on Chromium site
            dangers = {
                0: u'Not Dangerous',                 # The download is safe.
                1: u'Dangerous',                     # A dangerous file to the system (e.g.: a pdf or extension from places
                                                     # other than gallery).
                2: u'Dangerous URL',                 # SafeBrowsing download service shows this URL leads to malicious file
                                                     # download.
                3: u'Dangerous Content',             # SafeBrowsing download service shows this file content as being
                                                     # malicious.
                4: u'Content May Be Malicious',      # The content of this download may be malicious (e.g., extension is exe
                                                     # but SafeBrowsing has not finished checking the content).
                5: u'Uncommon Content',              # SafeBrowsing download service checked the contents of the download,
                                                     # but didn't have enough data to determine whether it was malicious.
                6: u'Dangerous But User Validated',  # The download was evaluated to be one of the other types of danger,
                                                     # but the user told us to go ahead anyway.
                7: u'Dangerous Host',                # SafeBrowsing download service checked the contents of the download
                                                     # and didn't have data on this specific file, but the file was served
                                                     # from a host known to serve mostly malicious content.
                8: u'Potentially Unwanted'}          # Applications and extensions that modify browser and/or computer
                                                     # settings

            if self.danger_type in dangers.keys():
                self.danger_type_friendly = dangers[self.danger_type]
            elif self.danger_type is None:
                self.danger_type_friendly = None
            else:
                self.danger_type_friendly = u'[Error - Unknown Danger Code]'
                logging.error(" - Error decoding danger code for download '{}'".format(self.url))

        def decode_download_state(self):
            # from download_item.h on Chromium site
            states = {
                0: u"In Progress",   # Download is actively progressing.
                1: u"Complete",      # Download is completely finished.
                2: u"Cancelled",     # Download has been cancelled.
                3: u"Interrupted",   # '3' was the old "Interrupted" code until a bugfix in Chrome v22. 22+ it's '4'
                4: u"Interrupted"}   # This state indicates that the download has been interrupted.

            if self.state in states.keys():
                self.state_friendly = states[self.state]
            else:
                self.state_friendly = u"[Error - Unknown State]"
                logging.error(" - Error decoding download state for download '{}'".format(self.url))

        def create_friendly_status(self):
            try:
                status = u"%s -  %i%% [%i/%i]" % \
                         (self.state_friendly, (float(self.received_bytes) / float(self.total_bytes)) * 100,
                          self.received_bytes, self.total_bytes)
            except ZeroDivisionError:
                status = u"%s -  %i bytes" % (self.state_friendly, self.received_bytes)
            except:
                status = u"[parsing error]"
                logging.error(" - Error creating friendly status message for download '{}'".format(self.url))
            self.status_friendly = status

# Cache parsing functionality based on the Chromagnon project (https://github.com/JRBANCEL/Chromagnon) by Jean-Rémy Bancel.
# Modifications done by Ryan Benson (ryan@obsidianforensics.com) for improvements and integration with Hindsight.

# Original copyright notice from Chromagnon:

# Copyright (c) 2012, Jean-Rémy Bancel <jean-remy.bancel@telecom-paristech.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Chromagon Project nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Jean-Rémy Bancel BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


class CacheAddressError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class CacheAddress():
    """
    Object representing a Chrome Cache Address
    """
    SEPARATE_FILE = 0
    RANKING_BLOCK = 1
    BLOCK_256 = 2
    BLOCK_1024 = 3
    BLOCK_4096 = 4

    typeArray = [("Separate file", 0),
                 ("Ranking block file", 36),
                 ("256 bytes block file", 256),
                 ("1k bytes block file", 1024),
                 ("4k bytes block file", 4096)]

    def __init__(self, uint_32, path):
        """
        Parse the 32 bits of the uint_32
        """
        if uint_32 == 0:
            raise CacheAddressError("Null Address")

        #XXX Is self.binary useful ??
        self.addr = uint_32
        self.path = path

        # Checking that the MSB is set
        self.binary = bin(uint_32)
        if len(self.binary) != 34:
            raise CacheAddressError("Uninitialized Address")

        self.blockType = int(self.binary[3:6], 2)

        # If it is an address of a separate file
        if self.blockType == CacheAddress.SEPARATE_FILE:
            self.fileSelector = "f_%06x" % int(self.binary[6:], 2)
        elif self.blockType == CacheAddress.RANKING_BLOCK:
            self.fileSelector = "data_" + str(int(self.binary[10:18], 2))
        else:
            self.entrySize = CacheAddress.typeArray[self.blockType][1]
            self.contiguousBlock = int(self.binary[8:10], 2)
            self.fileSelector = "data_" + str(int(self.binary[10:18], 2))
            self.blockNumber = int(self.binary[18:], 2)

    def __str__(self):
        string = hex(self.addr) + " ("
        if self.blockType >= CacheAddress.BLOCK_256:
            string += str(self.contiguousBlock) +\
                      " contiguous blocks in "
        string += CacheAddress.typeArray[self.blockType][0] +\
                  " : " + self.fileSelector + ")"
        return string


class CacheData:
    """
    Retrieve data at the given address
    Can save it to a separate file for export
    """

    HTTP_HEADER = 0
    UNKNOWN = 1

    def __init__(self, address, size, isHTTPHeader=False):
        """
        It is a lazy evaluation object : the file is open only if it is
        needed. It can parse the HTTP header if asked to do so.
        See net/http/http_util.cc LocateStartOfStatusLine and
        LocateEndOfHeaders for details.
        """
        self.size = size
        self.address = address
        self.type = CacheData.UNKNOWN

        if isHTTPHeader and self.address.blockType != CacheAddress.SEPARATE_FILE:
            # Getting raw data
            string = ""
            block = open(os.path.join(self.address.path, self.address.fileSelector), 'rb')

            # Offset in file
            self.offset = 8192 + self.address.blockNumber*self.address.entrySize
            block.seek(self.offset)
            for _ in range(self.size):
                string += struct.unpack('c', block.read(1))[0]
            block.close()

            # Finding the beginning of the request
            start = re.search("HTTP", string)
            if start is None:
                return
            else:
                string = string[start.start():]

            # Finding the end (some null characters : verified by experience)
            end = re.search("\x00\x00", string)
            if end is None:
                return
            else:
                string = string[:end.end()-2]

            # Creating the dictionary of headers
            self.headers = {}
            for line in string.split('\0'):
                stripped = line.split(':')
                self.headers[stripped[0].lower()] = \
                    ':'.join(stripped[1:]).strip()
            self.type = CacheData.HTTP_HEADER

    def save(self, filename=None):
        """Save the data to the specified filename"""
        if self.address.blockType == CacheAddress.SEPARATE_FILE:
            shutil.copy(self.address.path + self.address.fileSelector,
                        filename)
        else:
            output = open(filename, 'wB')
            block = open(self.address.path + self.address.fileSelector, 'rb')
            block.seek(8192 + self.address.blockNumber*self.address.entrySize)
            output.write(block.read(self.size))
            block.close()
            output.close()

    def data(self):
        """Returns a string representing the data"""
        try:
            block = open(os.path.join(self.address.path, self.address.fileSelector), 'rb')
            block.seek(8192 + self.address.blockNumber*self.address.entrySize)
            data = block.read(self.size).decode('utf-8', errors="replace")
            block.close()
        except:
            logging.error(" - Error decoding cached URL")
            data = "<error>"
        return data

    def __str__(self):
        """
        Display the type of cacheData
        """
        if self.type == CacheData.HTTP_HEADER:
            if self.headers.has_key('content-type'):
                return "HTTP Header %s" % self.headers['content-type']
            else:
                return "HTTP Header"
        else:
            return "Data"


class CacheBlock:
    """
    Object representing a block of the cache. It can be the index file or any
    other block type : 256B, 1024B, 4096B, Ranking Block.
    See /net/disk_cache/disk_format.h for details.
    """

    INDEX_MAGIC = 0xC103CAC3
    BLOCK_MAGIC = 0xC104CAC3
    INDEX = 0
    BLOCK = 1

    def __init__(self, filename):
        """
        Parse the header of a cache file
        """
        header = open(filename, 'rb')

        # Read Magic Number
        magic = struct.unpack('I', header.read(4))[0]
        if magic == CacheBlock.BLOCK_MAGIC:
            self.type = CacheBlock.BLOCK
            header.seek(2, 1)
            self.version = struct.unpack('h', header.read(2))[0]
            self.header = struct.unpack('h', header.read(2))[0]
            self.nextFile = struct.unpack('h', header.read(2))[0]
            self.blockSize = struct.unpack('I', header.read(4))[0]
            self.entryCount = struct.unpack('I', header.read(4))[0]
            self.entryMax = struct.unpack('I', header.read(4))[0]
            self.empty = []
            for _ in range(4):
                self.empty.append(struct.unpack('I', header.read(4))[0])
            self.position = []
            for _ in range(4):
                self.position.append(struct.unpack('I', header.read(4))[0])
        elif magic == CacheBlock.INDEX_MAGIC:
            self.type = CacheBlock.INDEX
            header.seek(2, 1)
            self.version = struct.unpack('h', header.read(2))[0]
            self.entryCount = struct.unpack('I', header.read(4))[0]
            self.byteCount = struct.unpack('I', header.read(4))[0]
            self.lastFileCreated = "f_%06x" % struct.unpack('I', header.read(4))[0]
            header.seek(4*2, 1)
            self.tableSize = struct.unpack('I', header.read(4))[0]
        else:
            header.close()
            raise Exception("Invalid Chrome Cache File")
        header.close()


class CacheItem(Chrome.HistoryItem):
    def __init__(self, url, date_created, key, value, http_headers):
        super(CacheItem, self).__init__(u'cache', timestamp=date_created, name=key, value=value)
        self.url = url
        self.date_created = date_created
        self.key = key
        self.value = value
        self.http_headers = http_headers


class CacheEntry(Chrome.HistoryItem):
    """
    See /net/disk_cache/disk_format.h for details.
    """

    STATE = ["Normal (data cached)",
             "Evicted (data deleted)",
             "Doomed (data to be deleted)"]

    def __init__(self, address, row_type, timezone):
        """
        Parse a Chrome Cache Entry at the given address
        """

        super(CacheEntry, self).__init__(row_type, timestamp=None, name=None, value=None)

        self.httpHeader = None
        self.http_headers_dict = None
        self.timezone = timezone
        block = open(os.path.join(address.path, address.fileSelector), 'rb')

        # Going to the right entry
        block.seek(8192 + address.blockNumber*address.entrySize)

        # Parsing basic fields
        self.hash = struct.unpack('I', block.read(4))[0]
        self.next = struct.unpack('I', block.read(4))[0]
        self.rankingNode = struct.unpack('I', block.read(4))[0]
        self.usageCounter = struct.unpack('I', block.read(4))[0]
        self.reuseCounter = struct.unpack('I', block.read(4))[0]
        self.state = struct.unpack('I', block.read(4))[0]
        self.creationTime = to_datetime(struct.unpack('Q', block.read(8))[0], self.timezone)
        self.keyLength = struct.unpack('I', block.read(4))[0]
        self.keyAddress = struct.unpack('I', block.read(4))[0]

        dataSize = []
        for _ in range(4):
            dataSize.append(struct.unpack('I', block.read(4))[0])

        self.data = []
        for index in range(4):
            addr = struct.unpack('I', block.read(4))[0]
            try:
                addr = CacheAddress(addr, address.path)
                self.data.append(CacheData(addr, dataSize[index], True))
            except CacheAddressError:
                pass

        # Find the HTTP header if there is one
        for data in self.data:
            if data.type == CacheData.HTTP_HEADER:
                self.httpHeader = data
                header_dict = {}
                for header in data.__dict__['headers']:
                    try:
                        header_dict[header.decode('utf-8')] = data.__dict__['headers'][header].decode('utf-8')
                    except:
                        pass
                self.http_headers_dict = header_dict

        self.flags = struct.unpack('I', block.read(4))[0]

        # Skipping pad
        block.seek(5*4, 1)

        # Reading local key
        if self.keyAddress == 0:
            self.key = block.read(self.keyLength).decode('ascii')
        # Key stored elsewhere
        else:
            addr = CacheAddress(self.keyAddress, address.path)

            # It is probably an HTTP header
            self.key = CacheData(addr, self.keyLength, True)

        block.close()

        # Hindsight HistoryItem fields
        self.timestamp = self.creationTime
        self.name = CacheEntry.STATE[self.state]
        self.url = self.keyToStr()
        self.value = ""
        self.etag = ""
        self.server_name = ""
        self.last_modified = ""
        self.file_size = 0
        self.location = ""
        for _ in self.data:
            if _.type != 0:
                self.file_size += _.size
                # Check if we already have an address here; if so, add a text separator
                if len(self.location) > 0:
                    self.location += "; "
                if _.address.blockType == 0:
                    self.location += "{}".format(_.address.fileSelector)
                else:
                    self.location += "{} [{}]".format(_.address.fileSelector, _.offset)

        self.http_headers_str = ""
        if self.http_headers_dict is not None:
            if self.state == 0:
                self.value = "{} ({} bytes)".format(self.http_headers_dict.get('content-type'), self.file_size)
            self.server_name = self.http_headers_dict.get('server')
            self.etag = self.http_headers_dict.get('etag')
            self.last_modified = self.http_headers_dict.get('last-modified')

            for key, value in self.http_headers_dict.iteritems():
                if key and value:
                    self.http_headers_str += u"{}: {}\n".format(key, value)
                elif key:
                    self.http_headers_str += u"{}\n".format(key)
            self.http_headers_str = self.http_headers_str.rstrip()

    def keyToStr(self):
        """
        Since the key can be a string or a CacheData object, this function is an
        utility to display the content of the key whatever type is it.
        """
        if self.keyAddress == 0:
            return self.key
        else:
            return self.key.data()

    def __str__(self):

        string = "Hash: 0x%08x" % self.hash + '\n'
        if self.next != 0:
            string += "Next: 0x%08x" % self.next + '\n'
        string += "Usage Counter: %d" % self.usageCounter + '\n'\
                  "Reuse Counter: %d" % self.reuseCounter + '\n'\
                  "Creation Time: %s" % self.creationTime + '\n'
        if self.keyAddress != 0:
            string += "Key Address: 0x%08x" % self.keyAddress + '\n'
        string += "Key: %s" % self.key + '\n'
        if self.flags != 0:
            string += "Flags: 0x%08x" % self.flags + '\n'
        string += "State: %s" % CacheEntry.STATE[self.state]
        for data in self.data:
            string += "\nData (%d bytes) at 0x%08x : %s" % (data.size,
                                                            data.address.addr,
                                                            data)
        return string
