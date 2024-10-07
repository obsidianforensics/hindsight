import datetime
import json
import logging
import os
import shutil
import sqlite3
import struct
from pyhindsight import __version__
from pathlib import Path

log = logging.getLogger(__name__)


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def text_factory(row_data):
    try:
        return row_data.decode('utf-8')
    except UnicodeDecodeError:
        return row_data


def open_sqlite_db(chrome, database_path, database_name):
    log.info(f' - Reading from {database_name} in {database_path}')

    if not os.path.exists(os.path.join(database_path, database_name)):
        log.info(f'   - Failed; {database_name} does not exist in {database_path}')
        return False

    if chrome.no_copy:
        db_path_to_open = os.path.join(database_path, database_name)

    else:
        try:
            # Create 'temp' directory if it doesn't exist
            Path(chrome.temp_dir).mkdir(parents=True, exist_ok=True)

            # Copy database to temp directory
            db_path_to_open = os.path.join(chrome.temp_dir, database_name)
            shutil.copyfile(os.path.join(database_path, database_name), db_path_to_open)
        except Exception as e:
            log.error(f' - Error copying {database_name}: {e}')
            return None

    try:
        # Connect to copied database
        db_conn = sqlite3.connect(db_path_to_open)

        # Use a dictionary cursor
        db_conn.row_factory = dict_factory
        db_conn.text_factory = text_factory

        # Execute a test query to make sure the database is not corrupted
        db_conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")

    except Exception as e:
        log.error(f' - Error opening {database_name}: {e}')
        return None

    return db_conn


def format_plugin_output(name, version, items):
    width = 80
    left_side = width * 0.55
    full_plugin_name = "{} (v{})".format(name, version)
    pretty_name = f"{full_plugin_name:>{int(left_side)}}:{' '.join(['-', items, '-']):^{(width - int(left_side) - 2)}}"
    return pretty_name


def format_meta_output(name, content):
    left_side = 17
    pretty_name = "{name:>{left_width}}: {content}" \
        .format(name=name, left_width=int(left_side), content=content)
    return pretty_name


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return str(obj, encoding='utf-8', errors='replace')
        else:
            return obj.__dict__


def to_datetime(timestamp, timezone=None):
    """Convert a variety of timestamp formats to a datetime object."""

    try:
        if isinstance(timestamp, datetime.datetime):
            return timestamp
        try:
            timestamp = float(timestamp)
        except Exception as e:
            log.warning(f'Exception parsing {timestamp} to datetime: {e}')
            return datetime.datetime.fromtimestamp(0, datetime.UTC)

        # Very big Webkit microseconds (18 digits), most often cookie expiry dates.
        if timestamp >= 253402300800000000:
            new_timestamp = datetime.datetime.max
            log.warning(f'Timestamp value {timestamp} is too large to convert; replaced with {datetime.datetime.max}')

        # Microsecond timestamps past 2038 can be problematic with datetime.fromtimestamp(timestamp).
        elif timestamp > 13700000000000000:
            new_timestamp = datetime.datetime.fromtimestamp(0, datetime.UTC) \
                            + datetime.timedelta(seconds=(timestamp / 1000000) - 11644473600)

        # Webkit microseconds (17 digits)
        elif timestamp > 12000000000000000:  # ts > 1981
            new_timestamp = datetime.datetime.fromtimestamp((timestamp / 1000000) - 11644473600, datetime.UTC)

        # Epoch microseconds (16 digits)
        elif 2500000000000000 > timestamp > 1280000000000000:  # 2049 > ts > 2010
            new_timestamp = datetime.datetime.fromtimestamp(timestamp / 1000000, datetime.UTC)

        # Epoch milliseconds (13 digits)
        elif 2500000000000 > timestamp > 1280000000000:  # 2049 > ts > 2010
            new_timestamp = datetime.datetime.fromtimestamp(timestamp / 1000, datetime.UTC)

        # Webkit seconds (11 digits)
        elif 15000000000 > timestamp >= 12900000000:  # 2076 > ts > 2009
            new_timestamp = datetime.datetime.fromtimestamp(timestamp - 11644473600, datetime.UTC)

        # Epoch seconds (10 digits typically, but could be less)
        else:
            try:
                new_timestamp = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
            except OSError as e:
                log.warning(f'Exception parsing {timestamp} to datetime: {e}; '
                            f'common issue is value is too big for the OS to convert it')
                return datetime.datetime.fromtimestamp(0, datetime.UTC)

        if timezone is not None:
            try:
                return new_timestamp.replace(tzinfo=datetime.UTC).astimezone(timezone)
            except NameError:
                return new_timestamp
        else:
            return new_timestamp
    except Exception as e:
        log.warning(f'Exception parsing {timestamp} to datetime: {e}')
        return datetime.datetime.fromtimestamp(0, datetime.UTC)


def friendly_date(timestamp):
    if isinstance(timestamp, (str, int)):
        return to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    elif timestamp is None:
        return ''
    else:
        return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def get_ldb_records(ldb_path, prefix=''):
    """Open a LevelDB at given path and return a list of records, optionally
    filtered by a prefix string. Key and value are kept as byte strings."""

    try:
        from ccl_chromium_reader.storage_formats import ccl_leveldb
    except ImportError:
        log.warning(f' - Failed to import ccl_leveldb; unable to process {ldb_path}')
        return []

    # The ldb key and value are both bytearrays, so the prefix must be too. We allow
    # passing the prefix into this function as a string for convenience.
    if isinstance(prefix, str):
        prefix = prefix.encode()

    try:
        db = ccl_leveldb.RawLevelDb(ldb_path)
    except Exception as e:
        log.warning(f' - Could not open {ldb_path} as LevelDB; {e}')
        return []

    cleaned_records = []

    try:
        for record in db.iterate_records_raw():
            cleaned_record = record.__dict__

            if record.file_type.name == 'Ldb':
                cleaned_record['key'] = record.key[:-8]

            if cleaned_record['key'].startswith(prefix):
                cleaned_record['key'] = cleaned_record['key'][len(prefix):]
                cleaned_record['state'] = cleaned_record['state'].name
                cleaned_record['file_type'] = cleaned_record['file_type'].name

                cleaned_records.append(cleaned_record)

    except ValueError:
        log.warning(' - Exception reading LevelDB: ValueError')

    except Exception as e:
        log.warning(f' - Exception reading LevelDB: {e}')

    db.close()
    return cleaned_records


def read_varint(source):
    result = 0
    bytes_used = 0
    for read in source:
        result |= ((read & 0x7F) << (bytes_used * 7))
        bytes_used += 1
        if (read & 0x80) != 0x80:
            return result, bytes_used


def read_string(input_bytes, ptr):
    length = struct.unpack('<i', input_bytes[ptr:ptr+4])[0]
    ptr += 4
    end_ptr = ptr+length
    string_value = input_bytes[ptr:end_ptr]
    while end_ptr % 4 != 0:
        end_ptr += 1

    return string_value.decode(), end_ptr


def read_int32(input_bytes, ptr):
    value = struct.unpack('<i', input_bytes[ptr:ptr + 4])[0]
    return value, ptr + 4


def read_int64(input_bytes, ptr):
    value = struct.unpack('<Q', input_bytes[ptr:ptr + 8])[0]
    return value, ptr + 8


banner = r'''
################################################################################

                   _     _           _     _       _     _
                  | |   (_)         | |   (_)     | |   | |
                  | |__  _ _ __   __| |___ _  __ _| |__ | |_
                  | '_ \| | '_ \ / _` / __| |/ _` | '_ \| __|
                  | | | | | | | | (_| \__ \ | (_| | | | | |_
                  |_| |_|_|_| |_|\__,_|___/_|\__, |_| |_|\__|
                                              __/ |
                       by ryan@hindsig.ht    |___/ v{}

################################################################################
'''.format(__version__)
