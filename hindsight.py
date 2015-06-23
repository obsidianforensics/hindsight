#!/usr/bin/env python

"""Hindsight - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome data folder, runs various plugins
against the data, and then outputs the results in a spreadsheet.
"""

import os
import sys
import re
import codecs
import time
import datetime
import argparse
import logging

# Try to import modules for different output formats, adding to output_formats array if successful
output_formats = []
try:
    import xlsxwriter
    output_formats.append('xlsx')
except ImportError:
    print "Couldn't import module 'xlsxwriter'; XLSX output disabled.\n"
    # logging.warning("Couldn't import module 'xlsxwriter'; XLSX output disabled")
try:
    import sqlite3
    output_formats.append('sqlite')
except ImportError:
    print "Couldn't import module 'sqlite3'; SQLite output disabled.\n"
try:
    import json
    output_formats.append('json')
except ImportError:
    print "Couldn't import module 'json'; JSON output disabled.\n"

# Try to import modules for cookie decryption on different OSes.
cookie_decryption = {'windows': 0, 'mac': 0, 'linux': 0}
# Windows
try:
    import win32crypt
    cookie_decryption['windows'] = 1
except ImportError:
    print "Couldn't import module 'win32crypt'; cookie decryption on Windows disabled.\n"
# Mac OS
try:
    import keyring
    cookie_decryption['mac'] = 1
except ImportError:
    print "Couldn't import module 'keyring'; cookie decryption on Mac OS disabled.\n"
# Linux / Mac OS
try:
    from Crypto.Cipher import AES
    cookie_decryption['linux'] = 1
except ImportError:
    print "Couldn't import module 'AES from Crypto.Cipher'; cookie decryption on Mac OS / Linux disabled.\n"
    cookie_decryption['linux'] = 0
    cookie_decryption['mac'] = 0
try:
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    print "Couldn't import module 'PBKDF2 from Crypto.Protocol.KDF'; cookie decryption on Mac OS / Linux disabled.\n"
    cookie_decryption['linux'] = 0
    cookie_decryption['mac'] = 0

try:
    import pytz
except ImportError:
    print "Couldn't import module 'pytz'; all timestamps in XLSX output will be in examiner local time ({}).".format(time.tzname[time.daylight])

__author__ = "Ryan Benson"
__version__ = "1.4.6"
__email__ = "ryan@obsidianforensics.com"


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class Chrome(object):
    def __init__(self, profile_path, version=None, structure=None, parsed_artifacts=None, installed_extensions=None,
                 artifacts_counts=None):
        self.profile_path = profile_path
        self.version = version
        self.structure = structure
        self.parsed_artifacts = parsed_artifacts
        self.installed_extensions = installed_extensions
        self.artifacts_counts = artifacts_counts

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

    def build_structure(self, path, database):

        if database not in self.structure.keys():
            self.structure[database] = {}

            # Connect to SQLite db
            database_path = os.path.join(path, database)
            db = sqlite3.connect(database_path)
            cursor = db.cursor()

            # Find the names of each table in the db
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
            except sqlite3.OperationalError:
                print "\nSQLite3 error; is the Chrome profile in use?  Hindsight cannot access history files " \
                      "if Chrome has them locked.  This error most often occurs when trying to analyze a local " \
                      "Chrome installation while it is running.  Please close Chrome and try again."
                exit()

            # For each table, find all the columns in it
            for table in tables:
                cursor.execute('PRAGMA table_info({})'.format(str(table[0])))
                columns = cursor.fetchall()

                # Create a dict of lists of the table/column names
                self.structure[database][str(table[0])] = []
                for column in columns:
                    self.structure[database][str(table[0])].append(str(column[1]))

    def to_epoch(self, timestamp):
        try:
            timestamp = float(timestamp)
        except:
            return 0
        if timestamp > 99999999999999:
            # Webkit
            return (float(timestamp) / 1000000) - 11644473600
        elif timestamp > 99999999999:
            # Epoch milliseconds
            return float(timestamp) / 1000
        elif timestamp >= 0:
            # Epoch
            return float(timestamp)
        else:
            return 0

    def to_datetime(self, timestamp):
        try:
            timestamp = float(timestamp)
        except:
            new_timestamp = datetime.datetime.utcfromtimestamp(0)
            return new_timestamp.replace(tzinfo=pytz.utc).astimezone(args.timezone)

        if 13700000000000000 > timestamp > 12000000000000000:  # 2035 > ts > 1981
            # Webkit
            new_timestamp = datetime.datetime.utcfromtimestamp((float(timestamp) / 1000000) - 11644473600)
            return new_timestamp.replace(tzinfo=pytz.utc).astimezone(args.timezone)
        elif 1900000000000 > timestamp > 2000000000:  # 2030 > ts > 1970
            # Epoch milliseconds
            new_timestamp = datetime.datetime.utcfromtimestamp(float(timestamp) / 1000)
            return new_timestamp.replace(tzinfo=pytz.utc).astimezone(args.timezone)
        elif 1900000000 > timestamp >= 0:  # 2030 > ts > 1970
            # Epoch
            new_timestamp = datetime.datetime.utcfromtimestamp(float(timestamp))
            return new_timestamp.replace(tzinfo=pytz.utc).astimezone(args.timezone)
        else:
            new_timestamp = datetime.datetime.utcfromtimestamp(0)
            return new_timestamp.replace(tzinfo=pytz.utc).astimezone(args.timezone)

    def friendly_date(self, timestamp):
        if isinstance(timestamp, (str, unicode, long, int)):
            return self.to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        else:
            return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def determine_version(self):
        """ Determine version of Chrome databases files by looking for combinations of columns in certain tables.

        Based on research I did to create "The Evolution of Chrome Databases Reference Chart"
        (http://www.obsidianforensics.com/blog/evolution-of-chrome-databases-chart/)
        """
        possible_versions = range(1, 43)

        def trim_lesser_versions_if(column, table, version):
            """Remove version numbers < 'version' from 'possible_versions' if 'column' isn't in 'table', and keep
            versions >= 'version' if 'column' is in 'table'.
            """
            if table:
                if column in table:
                    possible_versions[:] = [x for x in possible_versions if x >= version]
                else:
                    possible_versions[:] = [x for x in possible_versions if x < version]

        def trim_lesser_versions(version):
            """Remove version numbers > 'version' from 'possible_versions'"""
            possible_versions[:] = [x for x in possible_versions if x > version]

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

        if 'Cookies' in self.structure.keys():
            if 'cookies' in self.structure['Cookies'].keys():
                trim_lesser_versions_if('persistent', self.structure['Cookies']['cookies'], 17)
                trim_lesser_versions_if('priority', self.structure['Cookies']['cookies'], 28)
                trim_lesser_versions_if('encrypted_value', self.structure['Cookies']['cookies'], 33)

        if 'Web Data' in self.structure.keys():
            if 'autofill' in self.structure['Web Data'].keys():
                trim_lesser_versions_if('name', self.structure['Web Data']['autofill'], 2)
                trim_lesser_versions_if('date_created', self.structure['Web Data']['autofill'], 35)
            if 'autofill_profiles' in self.structure['Web Data'].keys():
                trim_lesser_versions_if('language_code', self.structure['Web Data']['autofill_profiles'], 36)
            if 'web_apps' not in self.structure['Web Data'].keys():
                trim_lesser_versions(37)

        if 'Login Data' in self.structure.keys():
            if 'logins' in self.structure['Login Data'].keys():
                trim_lesser_versions_if('display_name', self.structure['Login Data']['logins'], 39)
                trim_lesser_versions_if('generation_upload_status', self.structure['Login Data']['logins'], 42)

        self.version = possible_versions

    def get_history(self, path, history_file, version, row_type):
        # Set up empty return array
        results = []

        logging.info("History items from {}:".format(history_file))

        # TODO: visit_source table?  don't have good sample data
        # TODO: visits where visit_count = 0; means it should be in Archived History but could be helpful to have if
        # that file is missing.  Changing the first JOIN to a LEFT JOIN adds these in.

        # Queries for different versions
        query = {30: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
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
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    duration = None
                    if row.get('visit_duration'):
                        duration = datetime.timedelta(microseconds=row.get('visit_duration'))

                    new_row = URLItem(row.get('id'), row.get('url'), row.get('title'),
                                      self.to_datetime(row.get('visit_time')),
                                      self.to_datetime(row.get('last_visit_time')), row.get('visit_count'),
                                      row.get('typed_count'), row.get('from_visit'), row.get('transition'),
                                      row.get('hidden'), row.get('favicon_id'), row.get('is_indexed'),
                                      str(duration), row.get('source'))

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
                print("Couldn't open file")
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
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    # TODO: collapse download chain into one entry per download
                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    new_row = DownloadItem(row.get('id'), row.get('url'), row.get('received_bytes'),
                                           row.get('total_bytes'), row.get('state'), row.get('full_path'),
                                           self.to_datetime(row.get('start_time')),
                                           self.to_datetime(row.get('end_time')), row.get('target_path'),
                                           row.get('current_path'), row.get('opened'), row.get('danger_type'),
                                           row.get('interrupt_reason'), row.get('etag'), row.get('last_modified'),
                                           row.get('chain_index'))

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
                        new_row.value = 'Error retrieving download location'
                        logging.error(" - Error retrieving download location for download '{}'".format(new_row.url))

                    new_row.row_type = row_type
                    results.append(new_row)

                db_file.close()
                self.artifacts_counts[database + '_downloads'] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")
                logging.error(" - Couldn't open {}".format(os.path.join(path, database)))

    def get_cookies(self, path, database, version):
        def decrypt_cookie(encrypted_value):
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
                    if sys.platform == 'win32' and cookie_decryption['windows'] is 1:
                        try:
                            decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
                        except:
                            decrypted_value = "<encrypted>"
                    # If running Chrome on OSX
                    elif sys.platform == 'darwin' and cookie_decryption['mac'] is 1:
                        try:
                            my_pass = keyring.get_password('Chrome Safe Storage', 'Chrome')
                            my_pass = my_pass.encode('utf8')
                            iterations = 1003
                            key = PBKDF2(my_pass, salt, length, iterations)
                            decrypted_value = chrome_decrypt(encrypted_value, key=key)
                        except:
                            pass
                    else:
                        decrypted_value = "<encrypted>"

                    # If running Chromium on Linux.
                    # Unlike Win/Mac, we can decrypt Linux cookies without the user's pw
                    if decrypted_value is "<encrypted>" and cookie_decryption['linux'] is 1:
                        try:
                            my_pass = 'peanuts'.encode('utf8')
                            iterations = 1
                            key = PBKDF2(my_pass, salt, length, iterations)
                            decrypted_value = chrome_decrypt(encrypted_value, key=key)
                        except:
                            pass

            return decrypted_value

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

        # Get the lowest possible versionr from the version list, and decrement it until it finds a matching query
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
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    if row.get('encrypted_value') is not None:
                        if len(row.get('encrypted_value')) >= 2:
                            cookie_value = decrypt_cookie(row.get('encrypted_value'))
                        else:
                            cookie_value = row.get('value')
                    else:
                        cookie_value = row.get('value')

                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    new_row = CookieItem(row.get('host_key'), row.get('path'), row.get('name'), cookie_value,
                                         self.to_datetime(row.get('creation_utc')),
                                         self.to_datetime(row.get('last_access_utc')),
                                         self.to_datetime(row.get('expires_utc')), row.get('secure'),
                                         row.get('httponly'), row.get('persistent'),
                                         row.get('has_expires'), row.get('priority'))

                    accessed_row = CookieItem(row.get('host_key'), row.get('path'), row.get('name'), cookie_value,
                                              self.to_datetime(row.get('creation_utc')),
                                              self.to_datetime(row.get('last_access_utc')),
                                              self.to_datetime(row.get('expires_utc')), row.get('secure'),
                                              row.get('httponly'), row.get('persistent'),
                                              row.get('has_expires'), row.get('priority'))

                    new_row.url = (new_row.host_key + new_row.path)
                    accessed_row.url = (accessed_row.host_key + accessed_row.path)

                    # Create the row for when the cookie was created
                    new_row.row_type = 'cookie (created)'
                    new_row.timestamp = new_row.creation_utc
                    results.append(new_row)

                    # If the cookie was created and accessed at the same time (only used once), or if the last accessed
                    # time is 0 (happens on iOS), don't create an accessed row
                    if new_row.creation_utc != new_row.last_access_utc and \
                                    accessed_row.last_access_utc != self.to_datetime(0):
                                    # accessed_row.last_access_utc != datetime.datetime.utcfromtimestamp(0):
                        accessed_row.row_type = 'cookie (accessed)'
                        accessed_row.timestamp = accessed_row.last_access_utc
                        results.append(accessed_row)

                db_file.close()
                self.artifacts_counts['Cookies'] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")
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
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                # print 'cursor ',cursor.fetchall()

                for row in cursor:
                    if row.get('blacklisted_by_user') == 1:
                        blacklist_row = LoginItem(self.to_datetime(row.get('date_created')), url=row.get('action_url'),
                                                  name=row.get('username_element'),
                                                  value="<User chose to 'Never save password' for this site>",
                                                  count=row.get('times_used'))
                        blacklist_row.row_type = 'login (blacklist)'
                        results.append(blacklist_row)

                    if row.get('username_value') is not None and row.get('blacklisted_by_user') == 0:
                        username_row = LoginItem(self.to_datetime(row.get('date_created')), url=row.get('action_url'),
                                                 name=row.get('username_element'), value=row.get('username_value'),
                                                 count=row.get('times_used'))
                        username_row.row_type = 'login (username)'
                        results.append(username_row)

                    if row.get('password_value') is not None and row.get('blacklisted_by_user') == 0:
                        password = None
                        try:
                            # Windows is all I've had time to test; Ubuntu uses built-in password manager
                            password = win32crypt.CryptUnprotectData(row.get('password_value'), None, None, None, 0)[1]
                        except:
                            password = "<encrypted>"

                        password_row = LoginItem(self.to_datetime(row.get('date_created')), url=row.get('action_url'),
                                                 name=row.get('password_element'), value=password,
                                                 count=row.get('times_used'))
                        password_row.row_type = 'login (password)'
                        results.append(password_row)

                db_file.close()
                self.artifacts_counts['Login Data'] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")
                logging.error(" - Couldn't open {}".format(os.path.join(path, database)))

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
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    results.append(AutofillItem(self.to_datetime(row.get('date_created')), row.get('name'),
                                                row.get('value'), row.get('count')))

                    if row.get('date_last_used') and row.get('count') > 1:
                        results.append(AutofillItem(self.to_datetime(row.get('date_last_used')), row.get('name'),
                                                    row.get('value'), row.get('count')))

                db_file.close()
                self.artifacts_counts['Autofill'] = len(results)
                logging.info(" - Parsed {} items".format(len(results)))
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")
                logging.error(" - Couldn't open {}".format(os.path.join(path, database)))

    def get_bookmarks(self, path, file, version):
        # Set up empty return array
        results = []

        logging.info("Bookmark items from {}:".format(file))

        # Connect to 'Bookmarks' JSON file
        bookmarks_path = os.path.join(path, file)

        try:
            bookmarks_file = codecs.open(bookmarks_path, 'rb', encoding='utf-8')
            logging.info(" - Reading from file '{}'".format(bookmarks_path))
        except:
            logging.error(" - Error opening '{}'".format(bookmarks_path))
            return

        decoded_json = json.loads(bookmarks_file.read())

        # TODO: sync_id
        def process_bookmark_children(parent, children):
            for child in children:
                if child["type"] == "url":
                    results.append(BookmarkItem(self.to_datetime(child["date_added"]), child["name"], child["url"], parent))
                elif child["type"] == "folder":
                    new_parent = parent + " > " + child["name"]
                    results.append(BookmarkFolderItem(self.to_datetime(child["date_added"]), child["date_modified"],
                                                      child["name"], parent))
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

        # Grab file list of 'Local Storage' directory
        ls_path = os.path.join(path, dir_name)
        logging.info("Local Storage:")
        logging.info(" - Reading from {}".format(ls_path))

        local_storage_listing = os.listdir(ls_path)
        logging.debug(" - All {} files in Local Storage directory: {}".format(len(local_storage_listing), str(local_storage_listing)))
        filtered_listing = []

        for ls_file in local_storage_listing:
            if (ls_file[:3] == 'ftp' or ls_file[:4] == 'http' or ls_file[:16] == 'chrome-extension') and ls_file[-8:] != '-journal':
                filtered_listing.append(ls_file)
                ls_file_path = os.path.join(ls_path, ls_file)
                ls_created = os.stat(ls_file_path).st_ctime

                def to_unicode(raw_data):
                    if type(raw_data) in (int, long, float):
                        return unicode(raw_data, 'utf-8', 'replace')
                    elif type(raw_data) is unicode:
                        return raw_data
                    elif type(raw_data) is buffer:
                        try:
                            return str(raw_data).decode('utf-8', errors='replace')
                        except:
                            return "<buffer decode error>"
                    else:
                        return "<unknown type decode error>"

                # Connect to Local Storage file sqlite db
                try:
                    db_file = sqlite3.connect(ls_file_path)
                except:
                    logging.warning(" - Error opening {}".format(ls_file_path))
                    break

                # Use a dictionary cursor
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                try:
                    cursor.execute('SELECT key,value FROM ItemTable')
                    for row in cursor:
                        # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                        results.append(LocalStorageItem(ls_file, self.to_datetime(ls_created), row.get('key'),
                                                        to_unicode(row.get('value'))))
                except:
                    logging.warning(" - Error reading key/values from {}".format(ls_file_path))
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
                                    except:
                                        description = "<error>"
                                        logging.error(" - Error reading 'message' for {}".format(app_id))
                        else:
                            try:
                                description = decoded_manifest["description"]
                            except KeyError:
                                description = None
                                logging.warning(" - Error reading 'description' for {}".format(app_id))

                    results.append(BrowserExtension(app_id, name, description, decoded_manifest["version"]))
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
                                          self.friendly_date(prefs['browser']['last_clear_browsing_data_time']),
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

        self.artifacts_counts['Preferences'] = len(results)
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


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, buffer):
            return obj
        else:
            return obj.__dict__


class HistoryItem(object):
    def __init__(self, item_type, timestamp, url=None, name=None, value=None, interpretation=None):
        self.row_type = item_type
        self.timestamp = timestamp
        self.url = url
        self.name = name
        self.value = value
        self.interpretation = interpretation

    def __lt__(self, other):
        return self.timestamp < other.timestamp

    def __iter__(self):
        return iter(self.__dict__)


class URLItem(HistoryItem):
    def __init__(self, url_id, url, title, visit_time, last_visit_time, visit_count, typed_count, from_visit,
                 transition, hidden, favicon_id, indexed=None, visit_duration=None, visit_source=None,
                 transition_friendly=None):
        super(URLItem, self).__init__('url', timestamp=visit_time, url=url, name=title)
        self.url_id = url_id
        self.url = url
        self.title = title
        self.visit_time = visit_time
        self.last_visit_time = last_visit_time
        self.visit_count = visit_count
        self.typed_count = typed_count
        self.from_visit = from_visit
        self.transition = transition
        self.hidden = hidden
        self.favicon_id = favicon_id
        self.indexed = indexed
        self.visit_duration = visit_duration
        self.visit_source = visit_source
        self.transition_friendly = transition_friendly

    def decode_transition(self):
        # Source: http://src.chromium.org/svn/trunk/src/content/public/common/page_transition_types_list.h
        transition_friendly = {
            0: "link",                  # User got to this page by clicking a link on another page.
            1: "typed",                 # User got this page by typing the URL in the URL bar.  This should not be
                                        # used for cases where the user selected a choice that didn't look at all
                                        # like a URL; see GENERATED below.
                                        # We also use this for other "explicit" navigation actions.
            2: "auto bookmark",         # User got to this page through a suggestion in the UI, for example)
                                        # through the destinations page.
            3: "auto subframe",         # This is a subframe navigation. This is any content that is automatically
                                        # loaded in a non-toplevel frame. For example, if a page consists of
                                        # several frames containing ads, those ad URLs will have this transition
                                        # type. The user may not even realize the content in these pages is a
                                        # separate frame, so may not care about the URL (see MANUAL below).
            4: "manual subframe",       # For subframe navigations that are explicitly requested by the user and
                                        # generate new navigation entries in the back/forward list. These are
                                        # probably more important than frames that were automatically loaded in
                                        # the background because the user probably cares about the fact that this
                                        # link was loaded.
            5: "generated",             # User got to this page by typing in the URL bar and selecting an entry
                                        # that did not look like a URL.  For example, a match might have the URL
                                        # of a Google search result page, but appear like "Search Google for ...".
                                        # These are not quite the same as TYPED navigations because the user
                                        # didn't type or see the destination URL.
                                        # See also KEYWORD.
            6: "start page",            # This is a toplevel navigation. This is any content that is automatically
                                        # loaded in a toplevel frame.  For example, opening a tab to show the ASH
                                        # screen saver, opening the devtools window, opening the NTP after the safe
                                        # browsing warning, opening web-based dialog boxes are examples of
                                        # AUTO_TOPLEVEL navigations.
            7: "form submit",           # The user filled out values in a form and submitted it. NOTE that in
                                        # some situations submitting a form does not result in this transition
                                        # type. This can happen if the form uses script to submit the contents.
            8: "reload",                # The user "reloaded" the page, either by hitting the reload button or by
                                        # hitting enter in the address bar.  NOTE: This is distinct from the
                                        # concept of whether a particular load uses "reload semantics" (i.e.
                                        # bypasses cached data).  For this reason, lots of code needs to pass
                                        # around the concept of whether a load should be treated as a "reload"
                                        # separately from their tracking of this transition type, which is mainly
                                        # used for proper scoring for consumers who care about how frequently a
                                        # user typed/visited a particular URL.
                                        # SessionRestore and undo tab close use this transition type too.
            9: "keyword",               # The url was generated from a replaceable keyword other than the default
                                        # search provider. If the user types a keyword (which also applies to
                                        # tab-to-search) in the omnibox this qualifier is applied to the transition
                                        # type of the generated url. TemplateURLModel then may generate an
                                        # additional visit with a transition type of KEYWORD_GENERATED against the
                                        # url 'http://' + keyword. For example, if you do a tab-to-search against
                                        # wikipedia the generated url has a transition qualifer of KEYWORD, and
                                        # TemplateURLModel generates a visit for 'wikipedia.org' with a transition
                                        # type of KEYWORD_GENERATED.
            10: "keyword generated"}    # Corresponds to a visit generated for a keyword. See description of
                                        # KEYWORD for more details.

        qualifiers_friendly = {
            0x00800000: "Blocked",                 # A managed user attempted to visit a URL but was blocked.
            0x01000000: "Forward or Back",         # User used the Forward or Back button to navigate among browsing
                                                   # history.
            0x02000000: "From Address Bar",        # User used the address bar to trigger this navigation.
            0x04000000: "Home Page",               # User is navigating to the home page.
            0x08000000: "From API",                # The transition originated from an external application; the exact
                                                   # definition of this is embedder dependent.
            0x10000000: "Navigation Chain Start",  # The beginning of a navigation chain.
            0x20000000: "Navigation Chain End",    # The last transition in a redirect chain.
            0x40000000: "Client Redirect",         # Redirects caused by JavaScript or a meta refresh tag on the page.
            0x80000000: "Server Redirect"}         # Redirects sent from the server by HTTP headers. It might be nice to
                                                   # break this out into 2 types in the future, permanent or temporary,
                                                   # if we can get that information from WebKit.
        raw = self.transition
        core_mask = 0xff
        qualifier_mask = 0xffffff00
        code = raw & core_mask
        qualifier = raw & qualifier_mask

        if code in transition_friendly.keys():
            self.transition_friendly = transition_friendly[code]
            if qualifier in qualifiers_friendly.keys():
                self.transition_friendly += " (" + str(qualifiers_friendly[int(qualifier)]) + ")"

    def decode_source(self):
        # Source: https://code.google.com/p/chromium/codesearch#chromium/src/components/history/core/browser/history_types.h
        source_friendly = {
            0: "Synced",
            None: "Local",
            2: "Added by Extension",
            3: "Firefox (Imported)",
            4: "IE (Imported)",
            5: "Safari (Imported)"}

        raw = self.visit_source

        if raw in source_friendly.keys():
            self.visit_source = source_friendly[raw]


class DownloadItem(HistoryItem):
    def __init__(self, download_id, url, received_bytes, total_bytes, state, full_path=None, start_time=None,
                 end_time=None, target_path=None, current_path=None, opened=None, danger_type=None,
                 interrupt_reason=None, etag=None, last_modified=None, chain_index=None, interrupt_reason_friendly=None,
                 danger_type_friendly=None, state_friendly=None, status_friendly=None):
        super(DownloadItem, self).__init__('download', timestamp=start_time, url=url)
        self.download_id = download_id
        self.url = url
        self.received_bytes = received_bytes
        self.total_bytes = total_bytes
        self.state = state
        self.full_path = full_path
        self.start_time = start_time
        self.end_time = end_time
        self.target_path = target_path
        self.current_path = current_path
        self.opened = opened
        self.danger_type = danger_type
        self.interrupt_reason = interrupt_reason
        self.etag = etag
        self.last_modified = last_modified
        self.chain_index = chain_index
        self.interrupt_reason_friendly = interrupt_reason_friendly
        self.danger_type_friendly = danger_type_friendly
        self.state_friendly = state_friendly
        self.status_friendly = status_friendly

    def decode_interrupt_reason(self):
        interrupts = {
            0:  "No Interrupt",                 # Success

            # from download_interrupt_reason_values.h on Chromium site
            # File errors
            1:  "File Error",                   # Generic file operation failure.
            2:  "Access Denied",                # The file cannot be accessed due to security restrictions.
            3:  "Disk Full",                    # There is not enough room on the drive.
            5:  "Path Too Long",                # The directory or file name is too long.
            6:  "File Too Large",               # The file is too large for the file system to handle.
            7:  "Virus",                        # The file contains a virus.
            10: "Temporary Problem",            # The file was in use. Too many files are opened at once. We have run
                                                # out of memory.
            11: "Blocked",                      # The file was blocked due to local policy.
            12: "Security Check Failed",        # An attempt to check the safety of the download failed due to
                                                # unexpected reasons. See http://crbug.com/153212.
            13: "Resume Error",                 # An attempt was made to seek past the end of a file in opening a file
                                                # (as part of resuming a previously interrupted download).

            # Network errors
            20: "Network Error",                # Generic network failure.
            21: "Operation Timed Out",          # The network operation timed out.
            22: "Connection Lost",              # The network connection has been lost.
            23: "Server Down",                  # The server has gone down.

            # Server responses
            30: "Server Error",                 # The server indicates that the operation has failed (generic).
            31: "Range Request Error",          # The server does not support range requests. Internal use only:
                                                # must restart from the beginning.
            32: "Server Precondition Error",    # The download request does not meet the specified precondition.
                                                # Internal use only:  the file has changed on the server.
            33: "Unable to get file",           # The server does not have the requested data.

            # User input
            40: "Cancelled",                    # The user cancelled the download.
            41: "Browser Shutdown",             # The user shut down the browser. Internal use only:  resume pending
                                                # downloads if possible.

            # Crash
            50: "Browser Crashed"}              # The browser crashed. Internal use only:  resume pending downloads
                                                # if possible.

        if self.interrupt_reason in interrupts.keys():
            self.interrupt_reason_friendly = interrupts[self.interrupt_reason]
        elif self.interrupt_reason is None:
            self.interrupt_reason_friendly = None
        else:
            self.interrupt_reason_friendly = "[Error - Unknown Interrupt Code]"
            logging.error(" - Error decoding interrupt code for download '{}'".format(self.url))

    def decode_danger_type(self):
        # from download_danger_type.h on Chromium site
        dangers = {
            0: "Not Dangerous",                 # The download is safe.
            1: "Dangerous",                     # A dangerous file to the system (e.g.: a pdf or extension from places
                                                # other than gallery).
            2: "Dangerous URL",                 # SafeBrowsing download service shows this URL leads to malicious file
                                                # download.
            3: "Dangerous Content",             # SafeBrowsing download service shows this file content as being
                                                # malicious.
            4: "Content May Be Malicious",      # The content of this download may be malicious (e.g., extension is exe
                                                # but SafeBrowsing has not finished checking the content).
            5: "Uncommon Content",              # SafeBrowsing download service checked the contents of the download,
                                                # but didn't have enough data to determine whether it was malicious.
            6: "Dangerous But User Validated",  # The download was evaluated to be one of the other types of danger,
                                                # but the user told us to go ahead anyway.
            7: "Dangerous Host",                # SafeBrowsing download service checked the contents of the download
                                                # and didn't have data on this specific file, but the file was served
                                                # from a host known to serve mostly malicious content.
            8: "Potentially Unwanted"}          # Applications and extensions that modify browser and/or computer
                                                # settings

        if self.danger_type in dangers.keys():
            self.danger_type_friendly = dangers[self.danger_type]
        elif self.danger_type is None:
            self.danger_type_friendly = None
        else:
            self.danger_type_friendly = "[Error - Unknown Danger Code]"
            logging.error(" - Error decoding danger code for download '{}'".format(self.url))

    def decode_download_state(self):
        # from download_item.h on Chromium site
        states = {
            0: "In Progress",   # Download is actively progressing.
            1: "Complete",      # Download is completely finished.
            2: "Cancelled",     # Download has been cancelled.
            3: "Interrupted"}   # This state indicates that the download has been interrupted.

        if self.state in states.keys():
            self.state_friendly = states[self.state]
        else:
            self.state_friendly = "[Error - Unknown State]"
            logging.error(" - Error decoding download state for download '{}'".format(self.url))

    def create_friendly_status(self):
        try:
            status = "%s -  %i%% [%i/%i]" % \
                     (self.state_friendly, (float(self.received_bytes) / float(self.total_bytes)) * 100,
                      self.received_bytes, self.total_bytes)
        except ZeroDivisionError:
            status = "%s -  %i bytes" % (self.state_friendly, self.received_bytes)
        except:
            status = "[parsing error]"
            logging.error(" - Error creating friendly status message for download '{}'".format(self.url))
        self.status_friendly = status


class CookieItem(HistoryItem):
    def __init__(self, host_key, path, name, value, creation_utc, last_access_utc, expires_utc, secure, http_only,
                 persistent=None, has_expires=None, priority=None):
        super(CookieItem, self).__init__('cookie', timestamp=creation_utc, url=host_key, name=name, value=value)
        self.host_key = host_key
        self.path = path
        self.name = name
        self.value = value
        self.creation_utc = creation_utc
        self.last_access_utc = last_access_utc
        self.expires_utc = expires_utc
        self.secure = secure
        self.httponly = http_only
        self.persistent = persistent
        self.has_expires = has_expires
        self.priority = priority


class AutofillItem(HistoryItem):
    def __init__(self, date_created, name, value, count):
        super(AutofillItem, self).__init__('autofill', timestamp=date_created, name=name, value=value)
        self.date_created = date_created
        self.name = name
        self.value = value
        self.count = count


class BookmarkItem(HistoryItem):
    def __init__(self, date_added, name, url, parent_folder, sync_transaction_version=None):
        super(BookmarkItem, self).__init__('bookmark', timestamp=date_added, name=name, value=parent_folder)
        self.date_added = date_added
        self.name = name
        self.url = url
        self.parent_folder = parent_folder
        self.sync_transaction_version = sync_transaction_version


class BookmarkFolderItem(HistoryItem):
    def __init__(self, date_added, date_modified, name, parent_folder, sync_transaction_version=None):
        super(BookmarkFolderItem, self).__init__('bookmark folder', timestamp=date_added, name=name, value=parent_folder)
        self.date_added = date_added
        self.date_modified = date_modified
        self.name = name
        self.parent_folder = parent_folder
        self.sync_transaction_version = sync_transaction_version


class LocalStorageItem(HistoryItem):
    def __init__(self, url, date_created, key, value):
        super(LocalStorageItem, self).__init__('local storage', timestamp=date_created, name=key, value=value)
        self.url = url
        self.date_created = date_created
        self.key = key
        self.value = value


class BrowserExtension(object):
    def __init__(self, app_id, name, description, version):
        self.app_id = app_id
        self.name = name
        self.description = description
        self.version = version


class LoginItem(HistoryItem):
    def __init__(self, date_created, url, name, value, count):
        super(LoginItem, self).__init__('login', timestamp=date_created, url=url, name=name, value=value)
        self.date_created = date_created
        self.url = url
        self.name = name
        self.value = value
        self.count = count


def friendly_date(timestamp):
    return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def parse_arguments():
    description = '''
Hindsight v%s - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome data folder, runs various plugins
   against the data, and then outputs the results in a spreadsheet. ''' % __version__

    epi = '''
Example:  C:\>hindsight.py -i "C:\Users\Ryan\AppData\Local\Google\
                Chrome\User Data\Default" -o test_case

The Chrome data folder default locations are:
    WinXP:   <userdir>\Local Settings\Application Data\Google\Chrome
                \User Data\Default\\
    Vista/7: <userdir>\AppData\Local\Google\Chrome\User Data\Default\\
    Linux:   <userdir>/.config/google-chrome/Default/
    OS X:    <userdir>/Library/Application Support/Google/Chrome/Default/
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
    parser.add_argument('-f', '--format', choices=output_formats, default=output_formats[0], help='Output format')
    parser.add_argument('-m', '--mode', choices=['add', 'overwrite', 'exit'],
                        help='Output mode (what to do if output file already exists)')
    parser.add_argument('-l', '--log', help='Location Hindsight should log to (will append if exists)',
                        default='hindsight.log')
    parser.add_argument('-t', '--timezone', help='Display timezone for the timestamps in XLSX output', default='UTC')
    parser.add_argument('--decryptlinux', action='store_true',
                        help='Try to decrypt Chrome data from a Linux system - '
                             'this will cause problems if you try it on a non-Linux system')

    args = parser.parse_args()

    if not args.output:
        args.output = "Hindsight Internet History Analysis (%s)" % (time.strftime('%Y-%m-%dT%H-%M-%S'))

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

    # Disable decryption on Linux unless explicitly enabled
    if args.decryptlinux:
        cookie_decryption['linux'] = 1
    else:
        cookie_decryption['linux'] = 0

    return args


def main():
    global args
    args = parse_arguments()

    def write_excel(browser):
        workbook = xlsxwriter.Workbook(args.output + '.xlsx')
        w = workbook.add_worksheet('Timeline')

        # Define cell formats
        title_header_format  = workbook.add_format({'font_color': 'white', 'bg_color': 'gray', 'bold': 'true'})
        center_header_format = workbook.add_format({'font_color': 'black', 'align': 'center',  'bg_color': 'gray', 'bold': 'true'})
        header_format        = workbook.add_format({'font_color': 'black', 'bg_color': 'gray', 'bold': 'true'})
        black_type_format    = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_date_format    = workbook.add_format({'font_color': 'black', 'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        black_url_format     = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_field_format   = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_value_format   = workbook.add_format({'font_color': 'black', 'align': 'left',   'num_format': '0'})
        black_flag_format    = workbook.add_format({'font_color': 'black', 'align': 'center'})
        black_trans_format   = workbook.add_format({'font_color': 'black', 'align': 'left'})
        gray_type_format     = workbook.add_format({'font_color': 'gray',  'align': 'left'})
        gray_date_format     = workbook.add_format({'font_color': 'gray',  'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        gray_url_format      = workbook.add_format({'font_color': 'gray',  'align': 'left'})
        gray_field_format    = workbook.add_format({'font_color': 'gray',  'align': 'left'})
        gray_value_format    = workbook.add_format({'font_color': 'gray',  'align': 'left', 'num_format': '0'})
        red_type_format      = workbook.add_format({'font_color': 'red',   'align': 'left'})
        red_date_format      = workbook.add_format({'font_color': 'red',   'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        red_url_format       = workbook.add_format({'font_color': 'red',   'align': 'left'})
        red_field_format     = workbook.add_format({'font_color': 'red',   'align': 'right'})
        red_value_format     = workbook.add_format({'font_color': 'red',   'align': 'left', 'num_format': '0'})
        green_type_format    = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_date_format    = workbook.add_format({'font_color': 'green', 'num_format': 'yyyy-mm-dd hh:mm:ss.000'})
        green_url_format     = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_field_format   = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_value_format   = workbook.add_format({'font_color': 'green', 'align': 'left'})

        # Title bar
        w.merge_range('A1:G1', "Hindsight Internet History Forensics (v%s)" % __version__, title_header_format)
        w.merge_range('H1:L1', 'URL Specific',                                        center_header_format)
        w.merge_range('M1:Q1', 'Download Specific',                                   center_header_format)

        # Write column headers
        w.write(1, 0, "Type",                                                         header_format)
        w.write(1, 1, "Timestamp ({})".format(args.timezone),                         header_format)
        w.write(1, 2, "URL",                                                          header_format)
        w.write_rich_string(1, 3, "Title / Name / Status",                            header_format)
        w.write_rich_string(1, 4, "Data / Value / Path",                              header_format)
        w.write(1, 5, "Interpretation",                                               header_format)
        w.write(1, 6, "Source",                                                        header_format)
        w.write(1, 7, "Duration",                                                     header_format)
        w.write(1, 8, "Visit Count",                                                  header_format)
        w.write(1, 9, "Typed Count",                                                  header_format)
        w.write(1, 10, "URL Hidden",                                                  header_format)
        w.write(1, 11, "Transition",                                                  header_format)
        w.write(1, 12, "Interrupt Reason",                                            header_format)
        w.write(1, 13, "Danger Type",                                                 header_format)
        w.write(1, 14, "Opened?",                                                     header_format)
        w.write(1, 15, "ETag",                                                        header_format)
        w.write(1, 16, "Last Modified",                                               header_format)

        #Set column widths
        w.set_column('A:A', 16)         # Type
        w.set_column('B:B', 21)         # Date
        w.set_column('C:C', 60)         # URL
        w.set_column('D:D', 25)         # Title / Name / Status
        w.set_column('E:E', 80)         # Data / Value / Path
        w.set_column('F:F', 60)         # Interpretation
        w.set_column('G:G', 10)         # Source
        # URL Specific
        w.set_column('H:H', 14)         # Visit Duration
        w.set_column('I:K', 6)          # Visit Count, Typed Count, Hidden
        w.set_column('L:L', 12)         # Transition
        # Download Specific
        w.set_column('M:M', 12)         # Interrupt Reason
        w.set_column('N:N', 24)         # Danger Type
        w.set_column('O:O', 12)         # Opened
        w.set_column('P:P', 12)         # ETag
        w.set_column('Q:Q', 27)         # Last Modified

        print("\n Writing \"%s.xlsx\"" % args.output)
        row_number = 2
        for item in browser.parsed_artifacts:
            if item.row_type[:3] == "url":
                w.write_string(row_number, 0, item.row_type,                 black_type_format)   # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), black_date_format)   # date
                w.write_string(row_number, 2, item.url,                      black_url_format)    # URL
                w.write_string(row_number, 3, item.name,                     black_field_format)  # Title
                w.write(       row_number, 4, "",                            black_value_format)  # Indexed Content
                w.write(       row_number, 5, item.interpretation,           black_value_format)  # Interpretation
                w.write(       row_number, 6, item.visit_source,             black_type_format)   # Source
                w.write(       row_number, 7, item.visit_duration,           black_flag_format)   # Duration
                w.write(       row_number, 8, item.visit_count,              black_flag_format)   # Visit Count
                w.write(       row_number, 9, item.typed_count,              black_flag_format)   # Typed Count
                w.write(       row_number, 10, item.hidden,                  black_flag_format)   # Hidden
                w.write(       row_number, 11, item.transition_friendly,     black_trans_format)  # Transition

            if item.row_type == "autofill":
                w.write_string(row_number, 0, item.row_type,                 red_type_format)     # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), red_date_format)     # date
                w.write_string(row_number, 3, item.name,                     red_field_format)    # autofill field
                w.write_string(row_number, 4, item.value,                    red_value_format)    # autofill value
                w.write_string(row_number, 6, " ",                           red_type_format)     # blank

            if item.row_type == "download":
                w.write_string(row_number, 0, item.row_type,                 green_type_format)   # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), green_date_format)   # date
                w.write_string(row_number, 2, item.url,                      green_url_format)    # download URL
                w.write_string(row_number, 3, item.status_friendly,          green_field_format)  # % complete
                w.write_string(row_number, 4, item.value,                    green_value_format)  # download path
                w.write_string(row_number, 5, "",                            green_field_format)  # Interpretation (chain?)
                w.write(       row_number, 6, "",                            green_type_format)   # Safe Browsing
                w.write(       row_number, 12, item.interrupt_reason_friendly,green_value_format) # download path
                w.write(       row_number, 13, item.danger_type_friendly,    green_value_format)  # download path
                open_friendly = ""
                if item.opened == 1:
                    open_friendly = "Yes"
                elif item.opened == 0:
                    open_friendly = "No"
                w.write_string(row_number, 14, open_friendly, green_value_format)                 # opened
                w.write(row_number, 15, item.etag,            green_value_format)                 # ETag
                w.write(row_number, 16, item.last_modified,   green_value_format)                 # Last Modified

            if item.row_type == "bookmark":
                w.write_string(row_number, 0, item.row_type,  red_type_format)                    # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), red_date_format)     # date
                w.write_string(row_number, 2, item.url,       red_url_format)                     # URL
                w.write_string(row_number, 3, item.name,      red_value_format)                   # bookmark name
                w.write_string(row_number, 4, item.value,     red_value_format)                   # bookmark folder

            if item.row_type == "bookmark folder":
                w.write_string(row_number, 0, item.row_type,  red_type_format)                    # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), red_date_format)     # date
                w.write_string(row_number, 3, item.name,      red_value_format)                   # bookmark name
                w.write_string(row_number, 4, item.value,     red_value_format)                   # bookmark folder

            if item.row_type[:6] == "cookie":
                w.write_string(row_number, 0, item.row_type,  gray_type_format)                   # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), gray_date_format)    # date
                w.write_string(row_number, 2, item.url,       gray_url_format)                    # URL
                w.write_string(row_number, 3, item.name,      gray_field_format)                  # cookie name
                w.write_string(row_number, 4, item.value,     gray_value_format)                  # cookie value
                w.write(       row_number, 5, item.interpretation, gray_value_format)             # cookie interpretation

            if item.row_type == "local storage":
                w.write_string(row_number, 0, item.row_type,  gray_type_format)                   # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), gray_date_format)    # date
                w.write_string(row_number, 2, item.url,       gray_url_format)                    # URL
                w.write_string(row_number, 3, item.name,      gray_field_format)                  # cookie name
                w.write_string(row_number, 4, item.value,     gray_value_format)                  # cookie value
                w.write(       row_number, 5, item.interpretation, gray_value_format)             # cookie interpretation
                w.write_string(row_number, 6, " ",            gray_type_format)                   # blank

            if item.row_type[:5] == "login":
                w.write_string(row_number, 0, item.row_type,                 red_type_format)     # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), red_date_format)     # date
                w.write_string(row_number, 2, item.url,                      red_url_format)      # URL
                w.write_string(row_number, 3, item.name,                     red_field_format)    # form field name
                w.write_string(row_number, 4, item.value,                    red_value_format)    # username or pw value
                w.write_string(row_number, 6, " ",                           red_type_format)     # blank

            row_number += 1

        # Formatting
        w.freeze_panes(2, 0)                # Freeze top row
        w.autofilter(1, 0, row_number, 16)  # Add autofilter

        for item in browser.__dict__:
            try:
                if browser.__dict__[item]['presentation'] and browser.__dict__[item]['data']:
                    d = browser.__dict__[item]
                    p = workbook.add_worksheet(d['presentation']['title'])
                    title = d['presentation']['title']
                    if 'version' in d['presentation']:
                        title += " (v{})".format(d['presentation']['version'])
                    p.merge_range(0, 0, 0, len(d['presentation']['columns'])-1, "{}".format(title), title_header_format)
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
                    p.freeze_panes(2, 0)                                                       # Freeze top row
                    p.autofilter(1, 0, len(d['data'])+2, len(d['presentation']['columns'])-1)  # Add autofilter

            except:
                pass

        workbook.close()

    def write_sqlite(browser):
        output_file = args.output + '.sqlite'
        output_exists = None

        if os.path.exists(output_file):
            if os.path.getsize(output_file) > 0:
                output_exists = 1
                print "\nDatabase file \"%s\" already exists.\n" % output_file
                if not args.mode:
                    args.mode = raw_input('Would you like to (A)dd to it, (O)verwrite it, or (E)xit? ')
                add_re = re.compile(r'(^a$|add)', re.IGNORECASE)
                over_re = re.compile(r'(^o$|overwrite)', re.IGNORECASE)
                exit_re = re.compile(r'(^e$|exit)', re.IGNORECASE)
                if re.search(exit_re, args.mode):
                    print "Exiting... "
                    sys.exit()
                elif re.search(over_re, args.mode):
                    os.remove(output_file)
                    print "Deleted old \"%s\"" % output_file
                    args.mode = 'overwrite'
                elif re.search(add_re, args.mode):
                    args.mode = 'add'
                    print "Adding more records to existing \"%s\"" % output_file
                else:
                    print "Did not understand response.  Exiting... "
                    sys.exit()

        output_db = sqlite3.connect(output_file)

        with output_db:
            c = output_db.cursor()
            if args.mode == 'overwrite' or not output_exists:
                c.execute("CREATE TABLE timeline(type TEXT, timestamp TEXT, url TEXT, title TEXT, value TEXT, "
                          "interpretation TEXT, safe TEXT, visit_count INT, typed_count INT, url_hidden INT, "
                          "transition TEXT, interrupt_reason TEXT, danger_type TEXT, opened INT, etag TEXT, "
                          "last_modified TEXT)")

                c.execute("CREATE TABLE installed_extensions(name TEXT, description TEXT, version TEXT, app_id TEXT)")

            print("\n Writing \"%s.sqlite\"" % args.output)

            for item in browser.parsed_artifacts:
                if item.row_type == "url" or item.row_type == "url (archived)":
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, interpretation, visit_count, "
                              "typed_count, url_hidden, transition) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.interpretation,
                               item.visit_count, item.typed_count, item.hidden, item.transition_friendly))

                if item.row_type == "autofill":
                    c.execute("INSERT INTO timeline (type, timestamp, title, value, interpretation) "
                              "VALUES (?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.name, item.value, item.interpretation))

                if item.row_type == "download":
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation, "
                              "interrupt_reason, danger_type, opened, etag, last_modified) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.status_friendly, item.value,
                               item.interpretation, item.interrupt_reason_friendly, item.danger_type_friendly,
                               item.opened, item.etag, item.last_modified))

                if item.row_type == "bookmark":
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation))

                if item.row_type == "bookmark folder":
                    c.execute("INSERT INTO timeline (type, timestamp, title, value, interpretation) "
                              "VALUES (?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.name, item.value,
                               item.interpretation))

                if item.row_type == "cookie (created)" or item.row_type == "cookie (accessed)":
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation))

                if item.row_type == "local storage":
                    c.execute("INSERT INTO timeline (type, timestamp, url, title, value, interpretation) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value,
                               item.interpretation))

            for extension in browser.installed_extensions:
                c.execute("INSERT INTO installed_extensions (name, description, version, app_id) "
                          "VALUES (?, ?, ?, ?)",
                          (extension.name, extension.description, extension.version, extension.app_id))

    def format_plugin_output(name, version, items):
        width = 80
        left_side = width*0.55
        full_plugin_name = "{} (v{})".format(name, version)
        pretty_name = "{name:>{left_width}}:{count:^{right_width}}" \
            .format(name=full_plugin_name, left_width=int(left_side), version=version, count=' '.join(['-', items, '-']),
                    right_width=(width - int(left_side)-2))
        return pretty_name

    def format_meta_output(name, content):
        left_side = 17
        pretty_name = "{name:>{left_width}}: {content}" \
            .format(name=name, left_width=int(left_side), content=content)
        return pretty_name

    def format_processing_output(name, items):
        width = 80
        left_side = width*0.55
        count = '{:>6}'.format(str(items))
        pretty_name = "{name:>{left_width}}:{count:^{right_width}}" \
            .format(name=name, left_width=int(left_side), count=' '.join(['[', count, ']']),
                    right_width=(width - int(left_side)-2))
        return pretty_name

    # Set up logging
    logging.basicConfig(filename=args.log, level=logging.DEBUG, format='%(asctime)s.%(msecs).03d | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Hindsight version info
    print "\n Hindsight v%s" % __version__
    logging.info('\n' + '#'*80 + '\n###    Hindsight v{} (https://github.com/obsidianforensics/hindsight)    ###\n'.format(__version__) + '#'*80)
    logging.debug("Options: " + str(args))

    # Analysis start time
    print format_meta_output("Start time", str(datetime.datetime.now())[:-3])
    logging.info("Starting analysis")
    target_browser = Chrome(args.input)

    # Reading input directory
    print format_meta_output("Input directory", args.input)
    logging.info("Reading files from %s" % args.input)
    input_listing = os.listdir(args.input)
    logging.debug("Input directory contents: " + str(input_listing))
    print format_meta_output("Output name", args.output)

    print("\n Processing:")
    target_browser.structure = {}

    supported_databases = ['History', 'Archived History', 'Web Data', 'Cookies', 'Login Data']
    supported_subdirs = ['Local Storage', 'Extensions']
    supported_jsons = ['Bookmarks']  # , 'Preferences']
    supported_items = supported_databases + supported_subdirs + supported_jsons
    logging.debug("Supported items: " + str(supported_items))

    for input_file in input_listing:
        if input_file in supported_databases:
            # Process structure from Chrome database files
            target_browser.build_structure(args.input, input_file)

    # Use the structure of the input files to determine possible Chrome versions
    target_browser.determine_version()

    if len(target_browser.version) > 1:
        display_version = "%s-%s" % (target_browser.version[0], target_browser.version[-1])
    else:
        display_version = target_browser.version[0]

    print format_processing_output("Detected Chrome version", display_version)

    logging.info("Detected Chrome version %s" % display_version)

    logging.info("Found the following supported files or directories:")
    for input_file in input_listing:
        if input_file in supported_items:
            logging.info(" - %s" % input_file)

    # Process History files
    custom_type_re = re.compile(r'__([A-z0-9\._]*)$')
    for input_file in input_listing:
        if re.search(r'^History__|^History$', input_file):
            row_type = 'url'
            custom_type_m = re.search(custom_type_re, input_file)
            if custom_type_m:
                row_type = 'url ({})'.format(custom_type_m.group(1))
            target_browser.get_history(args.input, input_file, target_browser.version, row_type)
            display_type = 'URL' if not custom_type_m else 'URL ({})'.format(custom_type_m.group(1))
            print format_processing_output("{} records".format(display_type), target_browser.artifacts_counts[input_file])

            row_type = 'download'
            if custom_type_m:
                row_type = 'download ({})'.format(custom_type_m.group(1))
            target_browser.get_downloads(args.input, input_file, target_browser.version, row_type)
            display_type = 'Download' if not custom_type_m else 'Download ({})'.format(custom_type_m.group(1))
            print format_processing_output("{} records".format(display_type), target_browser.artifacts_counts[input_file + '_downloads'])

    if 'Archived History' in input_listing:
        target_browser.get_history(args.input, 'Archived History', target_browser.version, 'url (archived)')
        print format_processing_output("Archived URL records", target_browser.artifacts_counts['Archived History'])

    if 'Cookies' in input_listing:
        target_browser.get_cookies(args.input, 'Cookies', target_browser.version)
        print format_processing_output("Cookie records", target_browser.artifacts_counts['Cookies'])

    if 'Web Data' in input_listing:
        target_browser.get_autofill(args.input, 'Web Data', target_browser.version)
        print format_processing_output("Autofill records", target_browser.artifacts_counts['Autofill'])

    if 'Bookmarks' in input_listing:
        target_browser.get_bookmarks(args.input, 'Bookmarks', target_browser.version)
        print format_processing_output("Bookmark records", target_browser.artifacts_counts['Bookmarks'])

    if 'Local Storage' in input_listing:
        target_browser.get_local_storage(args.input, 'Local Storage')
        print format_processing_output("Local Storage records", target_browser.artifacts_counts['Local Storage'])

    if 'Extensions' in input_listing:
        target_browser.get_extensions(args.input, 'Extensions')
        print format_processing_output("Extensions", target_browser.artifacts_counts['Extensions'])

    if 'Login Data' in input_listing:
        target_browser.get_login_data(args.input, 'Login Data', target_browser.version)
        print format_processing_output("Login Data records", target_browser.artifacts_counts['Login Data'])

    if 'Preferences' in input_listing:
        target_browser.get_preferences(args.input, 'Preferences')
        print format_processing_output("Preference Items", target_browser.artifacts_counts['Preferences'])

    target_browser.parsed_artifacts.sort()
    print("\n Running plugins:")
    logging.info("Plugins:")

    plugin_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'plugins')
    sys.path.insert(0, plugin_path)

    try:
        plugin_listing = os.listdir(plugin_path)

        logging.debug(" - Contents of plugin folder: " + str(plugin_listing))
        for plugin in plugin_listing:
            if plugin[-3:] == ".py":
                plugin = plugin.replace(".py", "")
                module = __import__(plugin)
                logging.info("Running '{}' plugin".format(module.friendlyName))
                try:
                    parsed_items = module.plugin(target_browser)
                    print format_plugin_output(module.friendlyName, module.version, parsed_items)
                    logging.info(" - Completed; {}".format(parsed_items))
                except Exception, e:
                    print format_plugin_output(module.friendlyName, module.version, 'failed')
                    logging.info(" - Failed; {}".format(e))
    except Exception as e:
        logging.debug(' - Error loading plugins ({})'.format(e))
        print '  - Error loading plugins'

    if args.format == 'xlsx':
        logging.info("Writing output; XLSX format selected")
        try:
            write_excel(target_browser)
        except IOError:
            type, value, traceback = sys.exc_info()
            print value, "- is the file open?  If so, please close it and try again."
            logging.error("Error writing XLSX file; type: {}, value: {}, traceback: {}".format(type, value, traceback))

    elif args.format == 'json':
        logging.info("Writing output; JSON format selected")
        output = open(args.output, 'wb')
        output.write(json.dumps(target_browser, cls=MyEncoder, indent=4))

    elif args.format == 'sqlite':
        logging.info("Writing output; SQLite format selected")
        write_sqlite(target_browser)

    print "\n Finish time: ", str(datetime.datetime.now())[:-3]
    logging.info("Finish time: {}\n\n".format(str(datetime.datetime.now())[:-3]))

if __name__ == "__main__":
    main()
