#!/usr/bin/env python

"""Hindsight - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome data folder, runs various plugins
against the data, and then outputs the results in a spreadsheet. """

import sqlite3
import os
import sys
import json
import re
import codecs
# import unicodecsv
import time
import datetime
import xlsxwriter
import argparse

__author__ = "Ryan Benson"
__version__ = "1.1.0"
__email__ = "ryan@obsidianforensics.com"


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class Chrome(object):
    def __init__(self, profile_path, version=[], structure={}, parsed_artifacts=[], installed_extensions=[]):
        self.profile_path = profile_path
        self.version = version
        self.structure = structure
        self.parsed_artifacts = parsed_artifacts
        self.installed_extensions = installed_extensions

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
        if timestamp > 99999999999999:
            # Webkit
            return (int(timestamp)/1000000)-11644473600
        elif timestamp > 99999999999:
            # Epoch milliseconds
            return int(timestamp)/1000
        elif timestamp > 1:
            # Epoch
            return timestamp
        else:
            return "error"

    def friendly_date(self, timestamp):
        timestamp = int(timestamp)
        if timestamp > 99999999999999:
            # Webkit
            return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime((int(timestamp)/1000000)-11644473600))
        elif timestamp > 99999999999:
            # Epoch milliseconds
            return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(timestamp/1000))
        elif timestamp > 1:
            # Epoch
            return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(timestamp))
        else:
            return "error"

    def determine_version(self):
        """ Determine version of Chrome databases files by looking for combinations of columns in certain tables.

        Based on research I did to create "The Evolution of Chrome Databases Reference Chart"
        (http://www.obsidianforensics.com/blog/evolution-of-chrome-databases-chart/)
        """
        possible_versions = range(1, 36)

        def remove_versions(column, table, version):
            if table:
                if column in table:
                    possible_versions[:] = [x for x in possible_versions if x >= version]
                else:
                    possible_versions[:] = [x for x in possible_versions if x < version]

        if 'History' in self.structure.keys():
            if 'visits' in self.structure['History'].keys():
                remove_versions('visit_duration', self.structure['History']['visits'], 20)
            if 'visit_source' in self.structure['History'].keys():
                remove_versions('source', self.structure['History']['visit_source'], 7)
            if 'downloads' in self.structure['History'].keys():
                remove_versions('target_path', self.structure['History']['downloads'], 26)
                remove_versions('opened', self.structure['History']['downloads'], 16)
                remove_versions('etag', self.structure['History']['downloads'], 30)

        if 'Cookies' in self.structure.keys():
            if 'cookies' in self.structure['Cookies'].keys():
                remove_versions('persistent', self.structure['Cookies']['cookies'], 17)
                remove_versions('priority', self.structure['Cookies']['cookies'], 28)
                remove_versions('encrypted_value', self.structure['Cookies']['cookies'], 33)

        if 'Web Data' in self.structure.keys():
            if 'autofill' in self.structure['Web Data'].keys():
                remove_versions('name', self.structure['Web Data']['autofill'], 2)
                remove_versions('date_created', self.structure['Web Data']['autofill'], 35)

        self.version = possible_versions

    def get_history(self, path, history_file, version):
        # Set up empty return array
        results = []

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
                          FROM urls, visits WHERE urls.id = visits.url'''
        }

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            try:
                # Connect to 'History' sqlite db
                history_path = os.path.join(path, history_file)
                db_file = sqlite3.connect(history_path)

                # Use a dictionary cursor
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    new_row = URLItem(row.get('id'), row.get('url'), row.get('title'), self.to_epoch(row.get('visit_time')),
                                      row.get('last_visit_time'), row.get('visit_count'), row.get('typed_count'),
                                      row.get('from_visit'), row.get('transition'), row.get('hidden'),
                                      row.get('favicon_id'), row.get('is_indexed'), row.get('visit_duration'),
                                      row.get('source'))

                    if history_file == 'Archived History':
                        new_row.row_type = 'url (archived)'

                    new_row.decode_transition()

                    results.append(new_row)

                db_file.close()
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")

    def get_downloads(self, path, database, version):
        # Set up empty return array
        results = []

        # Connect to 'History' sqlite db
        history_path = os.path.join(path, database)
        db_file = sqlite3.connect(history_path)

        # Use a dictionary cursor
        db_file.row_factory = dict_factory
        cursor = db_file.cursor()

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
                        FROM downloads'''
        }

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            try:
                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    new_row = DownloadItem(row.get('id'), row.get('url'), row.get('received_bytes'), row.get('total_bytes'),
                                           row.get('state'), row.get('full_path'), self.to_epoch(row.get('start_time')),
                                           self.to_epoch(row.get('end_time')), row.get('target_path'), row.get('current_path'),
                                           row.get('opened'), row.get('danger_type'), row.get('interrupt_reason'),
                                           row.get('etag'), row.get('last_modified'), row.get('chain_index'))

                    new_row.decode_interrupt_reason()
                    new_row.decode_danger_type()
                    new_row.decode_download_state()
                    new_row.timestamp = new_row.start_time
                    # new_row.timestamp = self.to_epoch(new_row.start_time)

                    new_row.create_friendly_status()

                    if new_row.full_path is not None:
                        new_row.value = new_row.full_path
                    elif new_row.current_path is not None:
                        new_row.value = new_row.current_path
                    elif new_row.target_path is not None:
                        new_row.value = new_row.target_path
                    else:
                        new_row.value = 'Error retrieving download location'

                    results.append(new_row)

                db_file.close()
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")

    def get_cookies(self, path, database, version):
        # Set up empty return array
        results = []

        # Connect to 'Cookies' sqlite db
        db_path = os.path.join(path, database)
        db_file = sqlite3.connect(db_path)

        # Use a dictionary cursor
        db_file.row_factory = dict_factory
        cursor = db_file.cursor()

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
                        FROM cookies'''
        }

        # Get the lowest possible versionr from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            try:
                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    if row.get('encrypted_value') is not None:
                        if len(row.get('encrypted_value')) >= 2:
                            cookie_value = "<encrypted>"
                        else:
                            cookie_value = row.get('value')
                    else:
                        cookie_value = row.get('value')

                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    new_row = CookieItem(row.get('host_key'), row.get('path'), row.get('name'), cookie_value,
                                         self.to_epoch(row.get('creation_utc')), self.to_epoch(row.get('last_access_utc')),
                                         self.to_epoch(row.get('expires_utc')), row.get('secure'), row.get('httponly'),
                                         row.get('persistent'), row.get('has_expires'), row.get('priority'))

                    accessed_row = CookieItem(row.get('host_key'), row.get('path'), row.get('name'), cookie_value,
                                              self.to_epoch(row.get('creation_utc')), self.to_epoch(row.get('last_access_utc')),
                                              self.to_epoch(row.get('expires_utc')), row.get('secure'), row.get('httponly'),
                                              row.get('persistent'), row.get('has_expires'), row.get('priority'))

                    # new_row.url = new_row.host_key
                    new_row.url = (new_row.host_key + new_row.path)
                    accessed_row.url = (accessed_row.host_key + accessed_row.path)

                    # Create the row for when the cookie was created
                    new_row.row_type = 'cookie (created)'
                    new_row.timestamp = new_row.creation_utc
                    results.append(new_row)

                    # If the cookie was created and accessed at the same time (only used once), don't create an accessed row
                    if new_row.creation_utc != new_row.last_access_utc:
                        accessed_row.row_type = 'cookie (accessed)'
                        accessed_row.timestamp = accessed_row.last_access_utc
                        results.append(accessed_row)

                db_file.close()
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")

    def get_autofill(self, path, database, version):
        # Set up empty return array
        results = []

        # Connect to 'Web Data' sqlite db
        db_path = os.path.join(path, database)
        db_file = sqlite3.connect(db_path)

        # Use a dictionary cursor
        db_file.row_factory = dict_factory
        cursor = db_file.cursor()

        # TODO: add in autofill.last_used value, new in v35
        # Queries for different versions
        query = {35: '''SELECT autofill.date_created, autofill.name, autofill.value, autofill.count
                        FROM autofill''',
                 2:  '''SELECT autofill_dates.date_created, autofill.name, autofill.value, autofill.count
                        FROM autofill, autofill_dates WHERE autofill.pair_id = autofill_dates.pair_id'''
        }

        # Get the lowest possible version from the version list, and decrement it until it finds a matching query
        compatible_version = version[0]
        while compatible_version not in query.keys() and compatible_version > 0:
            compatible_version -= 1

        if compatible_version is not 0:
            try:
                # Use highest compatible version SQL to select download data
                cursor.execute(query[compatible_version])

                for row in cursor:
                    # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                    results.append(AutofillItem(self.to_epoch(row.get('date_created')), row.get('name'), row.get('value'), row.get('count')))

                db_file.close()
                self.parsed_artifacts.extend(results)

            except IOError:
                print("Couldn't open file")

    def get_bookmarks(self, path, file, version):
        # Set up empty return array
        results = []

        # Connect to 'Bookmarks' JSON file
        try:
            bookmarks_path = os.path.join(path, file)
            bookmarks_file = codecs.open(bookmarks_path, 'rb', encoding='utf-8')
        except IOError:
            print "No bookmarks file"
            return

        decoded_json = json.loads(bookmarks_file.read())

        # TODO: sync_id
        def process_bookmark_children(parent, children):
            for child in children:
                if child["type"] == "url":
                    results.append(BookmarkItem(self.to_epoch(child["date_added"]), child["name"], child["url"], parent))
                elif child["type"] == "folder":
                    new_parent = parent + " > " + child["name"]
                    results.append(BookmarkFolderItem(self.to_epoch(child["date_added"]), child["date_modified"], child["name"],
                                                      parent))
                    process_bookmark_children(new_parent, child["children"])

        for top_level_folder in decoded_json["roots"].keys():
            if top_level_folder != "sync_transaction_version" and top_level_folder != "synced" and top_level_folder != "meta_info":
                if decoded_json["roots"][top_level_folder]["children"] is not None:
                    process_bookmark_children(decoded_json["roots"][top_level_folder]["name"],
                                              decoded_json["roots"][top_level_folder]["children"])

        bookmarks_file.close()
        self.parsed_artifacts.extend(results)

    def get_local_storage(self, path, dir_name):
        results = []

        # Grab file list of 'Local Storage' directory
        ls_path = os.path.join(path, dir_name)
        local_storage_listing = os.listdir(ls_path)

        filtered_listing = []

        for ls_file in local_storage_listing:
            if (ls_file[:3] == 'ftp' or ls_file[:4] == 'http') and ls_file[-8:] != '-journal':
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
                    break

                # Use a dictionary cursor
                db_file.row_factory = dict_factory
                cursor = db_file.cursor()

                try:
                    cursor.execute('SELECT key,value FROM ItemTable')

                    for row in cursor:
                        # Using row.get(key) returns 'None' if the key doesn't exist instead of an error
                        results.append(LocalStorageItem(ls_file, ls_created, row.get('key'), to_unicode(row.get('value'))))

                except:
                    pass

        self.parsed_artifacts.extend(results)

    def get_extensions(self, path, dir_name):
        results = []

        # Grab listing of 'Extensions' directory
        ext_path = os.path.join(path, dir_name)
        ext_listing = os.listdir(ext_path)

        # Only process directories with the expected naming convention
        app_id_re = re.compile(r'^([a-z]{32})$')
        ext_listing = [x for x in ext_listing if app_id_re.match(x)]

        # Process each directory with an app_id name
        for app_id in ext_listing:
            # Get listing of the contents of app_id directory; should contain subdirs for each version of the extention.
            ext_vers_listing = os.path.join(ext_path, app_id)
            ext_vers = os.listdir(ext_vers_listing)

            # Connect to manifest.json in latest version directory
            try:
                manifest_path = os.path.join(ext_vers_listing, ext_vers[-1], 'manifest.json')
                manifest_file = codecs.open(manifest_path, 'rb', encoding='utf-8', errors='replace')
            except IOError:
                print "Error opening manifest file"

            name = None
            description = None

            if manifest_file:
                try:
                    decoded_manifest = json.loads(manifest_file.read())
                    if decoded_manifest["name"][:2] == '__':
                        if decoded_manifest["default_locale"]:
                            locale_messages_path = os.path.join(ext_vers_listing, ext_vers[-1], '_locales', decoded_manifest["default_locale"], 'messages.json')
                            locale_messages_file = codecs.open(locale_messages_path, 'rb', encoding='utf-8', errors='replace')
                            decoded_locale_messages = json.loads(locale_messages_file.read())
                            try:
                                name = decoded_locale_messages[decoded_manifest["name"][6:-2]]["message"]
                            except KeyError:
                                try:
                                    name = decoded_locale_messages[decoded_manifest["name"][6:-2]].lower["message"]
                                except:
                                    name = "<error>"
                    else:
                        try:
                            name = decoded_manifest["name"]
                        except KeyError:
                            name = None

                    if "description" in decoded_manifest.keys():
                        if decoded_manifest["description"][:2] == '__':
                            if decoded_manifest["default_locale"]:
                                locale_messages_path = os.path.join(ext_vers_listing, ext_vers[-1], '_locales', decoded_manifest["default_locale"], 'messages.json')
                                locale_messages_file = codecs.open(locale_messages_path, 'rb', encoding='utf-8', errors='replace')
                                decoded_locale_messages = json.loads(locale_messages_file.read())
                                try:
                                    description = decoded_locale_messages[decoded_manifest["description"][6:-2]]["message"]
                                except KeyError:
                                    try:
                                        description = decoded_locale_messages[decoded_manifest["description"][6:-2]].lower["message"]
                                    except:
                                        description = "<error>"
                        else:
                            try:
                                description = decoded_manifest["description"]
                            except KeyError:
                                description = None

                    results.append(BrowserExtension(app_id, name, description, decoded_manifest["version"]))

                except ValueError:
                    pass

        self.installed_extensions = results


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
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
            0:  "No Interrupt",               # Success

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

    def create_friendly_status(self):
        try:
            status = "%s -  %i%% [%i/%i]" % \
                     (self.state_friendly, (float(self.received_bytes)/float(self.total_bytes))*100,
                      self.received_bytes, self.total_bytes)
        except ZeroDivisionError:
            status = "%s -  %i bytes" % (self.state_friendly, self.received_bytes)
        except:
            status = "[parsing error]"
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


def friendly_date(timestamp):
    if timestamp > 99999999999999:
        # Webkit
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime((int(timestamp)/1000000)-11644473600))
    elif timestamp > 99999999999:
        # Epoch milliseconds
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(timestamp/1000))
    elif timestamp > 1:
        # Epoch
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(timestamp))
    else:
        return "error"


def main():
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
    parser.add_argument('-f', '--format', choices=['xlsx', 'json', 'sqlite'], default='xlsx', help='Output format')
    parser.add_argument('-m', '--mode', choices=['add', 'overwrite', 'exit'],
                        help='Output mode (what to do if output file already exists)')

    args = parser.parse_args()

    if not args.output:
        args.output = "Hindsight Internet History Analysis (%s)" % (time.strftime('%Y-%m-%dT%H-%M-%S'))

    # TODO: finish csv option
    def write_csv(items, version, csv='out.csv'):
        outfile = open(csv, "wb")
        fieldnames = ['name', 'url']
        writer = unicodecsv.writer(outfile, skipinitialspace=True, quotechar=b'"', quoting=unicodecsv.QUOTE_ALL, lineterminator="\n", dialect='excel')
        # writer = unicodecsv.DictWriter(outfile, fieldnames=fieldnames, extrasaction='ignore')
        # writer = unicodecsv.writer(outfile, fieldnames=fieldnames)

        # print(type(items))
        # print(items)

        writer.writerow(["Hindsight Internet History Forensics (v1.0)", "Detected Chrome Version: " + str(version)])
        writer.writerow(["Type", "Timestamp", "URL", "Title / Name / Status", "Data / Value / Path", "Interpretation",
                         "Safe?", "Visit Count", "Typed Count", "URL Hidden", "Transition", "Interrupt Reason",
                         "Danger Type", "Opened?", "ETag", "Last Modified"])

        for item in items:
            display = {}
            # display["url"] = [item.row_type, item.timestamp, item.url, item.name, item.value, "", "", item.visit_count, item.typed_count, item.hidden, item.transition_friendy]
            # display["download"] = [item.row_type, item.timestamp, item.url]
            # print(item.url)
            # print(item)
            if item.row_type == "url" or item.row_type == "url (archived)":
                writer.writerow([item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value, "", "", item.visit_count, item.typed_count, item.hidden, item.transition_friendly])
            if item.row_type == "download":
                writer.writerow([item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value, "", "", "", "", "", "", item.interrupt_reason_friendly, item.danger_type_friendly, item.opened, item.etag, item.last_modified])
            if item.row_type == "autofill":
                writer.writerow([item.row_type, friendly_date(item.timestamp), "", item.name, item.value, "", "", "", "", "", ""])
            if item.row_type == "bookmark":
                writer.writerow([item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value, "", "", "", "", "", ""])
            if item.row_type == "bookmark folder":
                writer.writerow([item.row_type, friendly_date(item.timestamp), "", item.name, item.value, "", "", "", "", "", ""])
            if item.row_type == "cookie (created)" or item.row_type == "cookie (accessed)":
                writer.writerow([item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value, "", "", "", "", "", ""])
            if item.row_type == "local storage":
                writer.writerow([item.row_type, friendly_date(item.timestamp), item.url, item.name, item.value, "", "", "", "", "", ""])

    def write_excel(browser):
        workbook = xlsxwriter.Workbook(args.output + '.xlsx')
        w = workbook.add_worksheet('Timeline')

        # Define cell formats
        title_header_format  = workbook.add_format({'font_color': 'white', 'bg_color': 'gray', 'bold': 'true'})
        center_header_format = workbook.add_format({'font_color': 'black', 'align': 'center',  'bg_color': 'gray', 'bold': 'true'})
        header_format        = workbook.add_format({'font_color': 'black', 'bg_color': 'gray', 'bold': 'true'})
        black_type_format    = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_date_format    = workbook.add_format({'font_color': 'black', 'num_format': 'mm/dd/yyyy hh:mm:ss.000'})
        black_url_format     = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_field_format   = workbook.add_format({'font_color': 'black', 'align': 'left'})
        black_value_format   = workbook.add_format({'font_color': 'black', 'align': 'left',   'num_format': '0'})
        black_flag_format    = workbook.add_format({'font_color': 'black', 'align': 'center'})
        black_trans_format   = workbook.add_format({'font_color': 'black', 'align': 'left'})
        gray_type_format     = workbook.add_format({'font_color': 'gray',  'align': 'left'})
        gray_date_format     = workbook.add_format({'font_color': 'gray',  'num_format': 'mm/dd/yyyy hh:mm:ss'})
        gray_url_format      = workbook.add_format({'font_color': 'gray',  'align': 'left'})
        gray_field_format    = workbook.add_format({'font_color': 'gray',  'align': 'left'})
        gray_value_format    = workbook.add_format({'font_color': 'gray',  'align': 'left', 'num_format': '0'})
        red_type_format      = workbook.add_format({'font_color': 'red',   'align': 'left'})
        red_date_format      = workbook.add_format({'font_color': 'red',   'num_format': 'mm/dd/yyyy hh:mm:ss'})
        red_url_format       = workbook.add_format({'font_color': 'red',   'align': 'left'})
        red_field_format     = workbook.add_format({'font_color': 'red',   'align': 'right'})
        red_value_format     = workbook.add_format({'font_color': 'red',   'align': 'left', 'num_format': '0'})
        green_type_format    = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_date_format    = workbook.add_format({'font_color': 'green', 'num_format': 'mm/dd/yyyy hh:mm:ss'})
        green_url_format     = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_field_format   = workbook.add_format({'font_color': 'green', 'align': 'left'})
        green_value_format   = workbook.add_format({'font_color': 'green', 'align': 'left'})

        # Title bar
        w.merge_range('A1:G1', "Hindsight Internet History Forensics (v%s)" % __version__, title_header_format)
        w.merge_range('H1:K1', 'URL Specific',                                        center_header_format)
        w.merge_range('L1:P1', 'Download Specific',                                   center_header_format)

        # Write column headers
        w.write(1, 0, "Type",                                                         header_format)
        w.write(1, 1, "Timestamp",                                                    header_format)
        w.write(1, 2, "URL",                                                          header_format)
        w.write_rich_string(1, 3, "Title / Name / Status",                            header_format)
        w.write_rich_string(1, 4, "Data / Value / Path",                              header_format)
        w.write(1, 5, "Interpretation",                                               header_format)
        w.write(1, 6, "Safe?",                                                        header_format)
        w.write(1, 7, "Visit Count",                                                  header_format)
        w.write(1, 8, "Typed Count",                                                  header_format)
        w.write(1, 9, "URL Hidden",                                                   header_format)
        w.write(1, 10, "Transition",                                                  header_format)
        w.write(1, 11, "Interrupt Reason",                                            header_format)
        w.write(1, 12, "Danger Type",                                                 header_format)
        w.write(1, 13, "Opened?",                                                     header_format)
        w.write(1, 14, "ETag",                                                        header_format)
        w.write(1, 15, "Last Modified",                                               header_format)

        #Set column widths
        w.set_column('A:A', 16)         # Type
        w.set_column('B:B', 18)         # Date
        w.set_column('C:C', 60)         # URL
        w.set_column('D:D', 25)         # Title / Name / Status
        w.set_column('E:E', 80)         # Data / Value / Path
        w.set_column('F:F', 60)         # Interpretation
        w.set_column('G:G', 12)         # Safe Browsing
        # URL Specific
        w.set_column('H:J', 6)          # Visit Count, Typed Count, Hidden
        w.set_column('K:K', 12)         # Transition
        # Download Specific
        w.set_column('L:L', 12)         # Interrupt Reason
        w.set_column('M:M', 24)         # Danger Type
        w.set_column('N:N', 12)         # Opened
        w.set_column('O:O', 12)         # ETag
        w.set_column('P:P', 27)         # Last Modified

        print("\nWriting \"%s.xlsx\"..." % args.output)
        row_number = 2
        for item in browser.parsed_artifacts:
            if item.row_type == "url" or item.row_type == "url (archived)":
                w.write_string(row_number, 0, item.row_type,                 black_type_format)   # record_type
                w.write(       row_number, 1, friendly_date(item.timestamp), black_date_format)   # date
                w.write_string(row_number, 2, item.url,                      black_url_format)    # URL
                w.write_string(row_number, 3, item.name,                     black_field_format)  # Title
                w.write(       row_number, 4, "",                            black_value_format)  # Indexed Content
                w.write(       row_number, 5, item.interpretation,           black_value_format)  # Interpretation
                w.write(       row_number, 6, "",                            black_type_format)   # Safe Browsing
                w.write(       row_number, 7, item.visit_count,              black_flag_format)   # Visit Count
                w.write(       row_number, 8, item.typed_count,              black_flag_format)   # Typed Count
                w.write(       row_number, 9, item.hidden,                   black_flag_format)   # Hidden
                w.write_string(row_number, 10, item.transition_friendly,     black_trans_format)  # Transition

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
                w.write(       row_number, 11, item.interrupt_reason_friendly,green_value_format) # download path
                w.write(       row_number, 12, item.danger_type_friendly,    green_value_format)  # download path
                open_friendly = ""
                if item.opened == 1:
                    open_friendly = "Yes"
                elif item.opened == 0:
                    open_friendly = "No"
                w.write_string(row_number, 13, open_friendly, green_value_format)                 # opened
                w.write(row_number, 14, item.etag,            green_value_format)                 # ETag
                w.write(row_number, 15, item.last_modified,   green_value_format)                 # Last Modified

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

            if item.row_type == "cookie (created)" or item.row_type == "cookie (accessed)":
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

            row_number += 1

        # Formatting
        w.freeze_panes(2, 0)                # Freeze top row
        w.autofilter(1, 0, row_number, 15)  # Add autofilter

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
                c.execute("CREATE TABLE timeline(type TEXT, timestamp INT, url TEXT, title TEXT, value TEXT, "
                          "interpretation TEXT, safe TEXT, visit_count INT, typed_count INT, url_hidden INT, "
                          "transition TEXT, interrupt_reason TEXT, danger_type TEXT, opened INT, etag TEXT, "
                          "last_modified TEXT)")

                c.execute("CREATE TABLE installed_extensions(name TEXT, description TEXT, version TEXT, app_id TEXT)")

            print("\nWriting \"%s.sqlite\"..." % args.output)

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

    print "\nHindsight v%s\n" % __version__

    print "Start time: ", datetime.datetime.now()
    target_browser = Chrome(args.input)
    print("\nReading files from %s..." % (args.input))

    input_listing = os.listdir(args.input)

    target_browser.structure = {}

    supported_databases = ['History', 'Archived History', 'Web Data', 'Cookies']
    supported_subdirs = ['Local Storage', 'Extensions']
    supported_jsons = ['Bookmarks']  #, 'Preferences']
    supported_items = supported_databases + supported_subdirs + supported_jsons

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

    print("\nDetected Chrome version %s\n" % display_version)

    print("Found the following supported files or directories:")
    for input_file in input_listing:
        if input_file in supported_items:
            print(" - %s" % input_file)

    # Process History files
    print "\nProcessing files..."
    if 'History' in input_listing:
        target_browser.get_history(args.input, 'History', target_browser.version)
        target_browser.get_downloads(args.input, 'History', target_browser.version)
    if 'Archived History' in input_listing:
        target_browser.get_history(args.input, 'Archived History', target_browser.version)
    if 'Cookies' in input_listing:
        target_browser.get_cookies(args.input, 'Cookies', target_browser.version)
    if 'Web Data' in input_listing:
        target_browser.get_autofill(args.input, 'Web Data', target_browser.version)
    if 'Bookmarks' in input_listing:
        target_browser.get_bookmarks(args.input, 'Bookmarks', target_browser.version)
    if 'Local Storage' in input_listing:
        target_browser.get_local_storage(args.input, 'Local Storage')
    if 'Extensions' in input_listing:
        target_browser.get_extensions(args.input, 'Extensions')

    target_browser.parsed_artifacts.sort()
    sys.path.insert(0, 'plugins')
    print("\nRunning plugins...")

    plugin_path = os.path.join(".", 'plugins')
    plugin_listing = os.listdir(plugin_path)

    for plugin in plugin_listing:
        if plugin[-3:] == ".py":
            plugin = plugin.replace(".py", "")
            module = __import__(plugin)
            print " - " + module.friendlyName + " [v" + module.version + "]"
            module.plugin(target_browser)

    if args.format == 'xlsx':
        try:
            write_excel(target_browser)
        except IOError:
            type, value, traceback = sys.exc_info()
            print value, "- is the file open?  If so, please close it and try again."

    elif args.format == 'json':
        output = open(args.output, 'wb')
        output.write(json.dumps(target_browser, cls=MyEncoder, indent=4))

    elif args.format == 'sqlite':
        write_sqlite(target_browser)

    # elif args.format == 'csv':
    #    write_csv(target_browser.parsed_artifacts, target_browser.version)

    print "\nFinish time: ", datetime.datetime.now()

if __name__ == "__main__":
    main()
