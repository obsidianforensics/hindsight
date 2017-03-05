import sqlite3
import os
import sys
import logging


class WebBrowser(object):
    def __init__(self, profile_path, browser_name, cache_path=None, version=None, display_version=None, timezone=None, structure=None,
                 parsed_artifacts=None, artifacts_counts=None, artifacts_display=None):
        self.profile_path = profile_path
        self.browser_name = browser_name
        self.cache_path = cache_path
        self.version = version
        self.display_version = display_version
        self.timezone = timezone
        self.structure = structure
        self.parsed_artifacts = parsed_artifacts
        self.artifacts_counts = artifacts_counts
        self.artifacts_display = artifacts_display
        # self.logger = logger

        if self.version is None:
            self.version = []

        if self.parsed_artifacts is None:
            self.parsed_artifacts = []

        if self.artifacts_counts is None:
            self.artifacts_counts = {}

        if self.artifacts_display is None:
            self.artifacts_display = {}

        # if self.logger is None:
        #     self.logger = logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs).03d | %(message)s',
        #                                       datefmt='%Y-%m-%d %H:%M:%S')

    @staticmethod
    def format_processing_output(name, items):
        width = 80
        left_side = width*0.55
        count = '{:>6}'.format(str(items))
        pretty_name = "{name:>{left_width}}:{count:^{right_width}}" \
            .format(name=name, left_width=int(left_side), count=' '.join(['[', count, ']']),
                    right_width=(width - int(left_side)-2))
        return pretty_name

    def build_structure(self, path, database):

        if database not in self.structure.keys():
            self.structure[database] = {}

            # Connect to SQLite db
            database_path = os.path.join(path, database)
            try:
                db = sqlite3.connect(database_path)
                cursor = db.cursor()
            except sqlite3.OperationalError:
                print "Not a database"
                return

            # Find the names of each table in the db
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
            except sqlite3.OperationalError:
                print "\nSQLite3 error; is the Chrome profile in use?  Hindsight cannot access history files " \
                      "if Chrome has them locked.  This error most often occurs when trying to analyze a local " \
                      "Chrome installation while it is running.  Please close Chrome and try again."
                sys.exit(1)
            except:
                logging.error(" - Couldn't connect to {}".format(database_path))
                return

            # For each table, find all the columns in it
            for table in tables:
                cursor.execute('PRAGMA table_info({})'.format(str(table[0])))
                columns = cursor.fetchall()

                # Create a dict of lists of the table/column names
                self.structure[database][str(table[0])] = []
                for column in columns:
                    self.structure[database][str(table[0])].append(str(column[1]))

    @staticmethod
    def dict_factory(cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

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
            super(WebBrowser.URLItem, self).__init__('url', timestamp=visit_time, url=url, name=title)
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

    class DownloadItem(HistoryItem):
        def __init__(self, download_id, url, received_bytes, total_bytes, state, full_path=None, start_time=None,
                     end_time=None, target_path=None, current_path=None, opened=None, danger_type=None,
                     interrupt_reason=None, etag=None, last_modified=None, chain_index=None, interrupt_reason_friendly=None,
                     danger_type_friendly=None, state_friendly=None, status_friendly=None):
            super(WebBrowser.DownloadItem, self).__init__(u'download', timestamp=start_time, url=url)
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

    class CookieItem(HistoryItem):
        def __init__(self, host_key, path, name, value, creation_utc, last_access_utc, expires_utc, secure, http_only,
                     persistent=None, has_expires=None, priority=None):
            super(WebBrowser.CookieItem, self).__init__('cookie', timestamp=creation_utc, url=host_key, name=name, value=value)
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
            super(WebBrowser.AutofillItem, self).__init__(u'autofill', timestamp=date_created, name=name, value=value)
            self.date_created = date_created
            self.name = name
            self.value = value
            self.count = count

    class BookmarkItem(HistoryItem):
        def __init__(self, date_added, name, url, parent_folder, sync_transaction_version=None):
            super(WebBrowser.BookmarkItem, self).__init__(u'bookmark', timestamp=date_added, name=name, value=parent_folder)
            self.date_added = date_added
            self.name = name
            self.url = url
            self.parent_folder = parent_folder
            self.sync_transaction_version = sync_transaction_version

    class BookmarkFolderItem(HistoryItem):
        def __init__(self, date_added, date_modified, name, parent_folder, sync_transaction_version=None):
            super(WebBrowser.BookmarkFolderItem, self).__init__(u'bookmark folder', timestamp=date_added, name=name, value=parent_folder)
            self.date_added = date_added
            self.date_modified = date_modified
            self.name = name
            self.parent_folder = parent_folder
            self.sync_transaction_version = sync_transaction_version

    class LocalStorageItem(HistoryItem):
        def __init__(self, url, date_created, key, value):
            super(WebBrowser.LocalStorageItem, self).__init__(u'local storage', timestamp=date_created, name=key, value=value)
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
            super(WebBrowser.LoginItem, self).__init__(u'login', timestamp=date_created, url=url, name=name, value=value)
            self.date_created = date_created
            self.url = url
            self.name = name
            self.value = value
            self.count = count
