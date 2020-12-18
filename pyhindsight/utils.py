import datetime
import json
import logging
import os
import pytz
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


def open_sqlite_db(chrome, database_path, database_name):
    log.info(f' - Reading from {database_name} in {database_path}')

    if chrome.no_copy:
        db_path_to_open = os.path.join(database_path, database_name)

    else:
        try:
            # Create 'temp' directory if doesn't exists
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
    except Exception as e:
        log.error(f' - Error opening {database_name}: {e}')
        return None

    return db_conn


def format_plugin_output(name, version, items):
    width = 80
    left_side = width * 0.55
    full_plugin_name = "{} (v{})".format(name, version)
    pretty_name = "{name:>{left_width}}:{count:^{right_width}}" \
        .format(name=full_plugin_name, left_width=int(left_side), version=version, count=' '.join(['-', items, '-']),
                right_width=(width - int(left_side) - 2))
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
        elif isinstance(obj, buffer):
            return str(obj, encoding='utf-8', errors='replace')
        else:
            return obj.__dict__


def to_epoch(timestamp):
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


def to_datetime(timestamp, timezone=None):
    """Convert a variety of timestamp formats to a datetime object."""

    try:
        if isinstance(timestamp, datetime.datetime):
            return timestamp
        try:
            timestamp = float(timestamp)
        except:
            timestamp = 0

        if 13700000000000000 > timestamp > 12000000000000000:  # 2035 > ts > 1981
            # Webkit
            new_timestamp = datetime.datetime.utcfromtimestamp((float(timestamp) / 1000000) - 11644473600)
        elif 1900000000000 > timestamp > 1380000000000:  # 2030 > ts > 2013
            # Epoch milliseconds
            new_timestamp = datetime.datetime.utcfromtimestamp(float(timestamp) / 1000)
        elif 13800000000 > timestamp >= 12900000000:  # 2038 > ts > 2009
            # Webkit seconds
            new_timestamp = datetime.datetime.utcfromtimestamp(float(timestamp) - 11644473600)
        elif 1900000000 > timestamp >= 1380000000:  # 2030 > ts > 2013
            # Epoch
            new_timestamp = datetime.datetime.utcfromtimestamp(float(timestamp))
        else:
            new_timestamp = datetime.datetime.utcfromtimestamp(0)

        if timezone is not None:
            try:
                return new_timestamp.replace(tzinfo=pytz.utc).astimezone(timezone)
            except NameError:
                return new_timestamp
        else:
            return new_timestamp
    except Exception as e:
        print(e)


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
        from pyhindsight.lib.ccl_chrome_indexeddb import ccl_leveldb
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
        log.warning(f' - Couldn\'t open {ldb_path} as LevelDB; {e}')
        return []

    cleaned_records = []

    for record in db.iterate_records_raw():
        cleaned_record = record.__dict__

        if record.file_type.name == 'Ldb':
            cleaned_record['key'] = record.key[:-8]

        if cleaned_record['key'].startswith(prefix):
            cleaned_record['key'] = cleaned_record['key'][len(prefix):]

        cleaned_record['state'] = cleaned_record['state'].name
        cleaned_record['file_type'] = cleaned_record['file_type'].name

        cleaned_records.append(cleaned_record)

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

#
# def create_temp_db(path, database):
#
#     # Create 'temp' directory if doesn't exists
#     Path(temp_directory_name).mkdir(parents=True, exist_ok=True)
#
#     # Copy database to temp directory
#     shutil.copyfile(os.path.join(path, database), os.path.join(temp_directory_name, database))

#
# def get_temp_db_directory():
#     return temp_directory_name


banner = '''
################################################################################

                   _     _           _     _       _     _
                  | |   (_)         | |   (_)     | |   | |
                  | |__  _ _ __   __| |___ _  __ _| |__ | |_
                  | '_ \| | '_ \ / _` / __| |/ _` | '_ \| __|
                  | | | | | | | | (_| \__ \ | (_| | | | | |_
                  |_| |_|_|_| |_|\__,_|___/_|\__, |_| |_|\__|
                                              __/ |
                        by @_RyanBenson      |___/   v{}

################################################################################
'''.format(__version__)
