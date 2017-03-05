import json
import datetime
import pytz
from pyhindsight import __version__


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
            return unicode(obj, encoding='utf-8', errors='replace')
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
        elif 1900000000000 > timestamp > 2000000000:  # 2030 > ts > 1970
            # Epoch milliseconds
            new_timestamp = datetime.datetime.utcfromtimestamp(float(timestamp) / 1000)
        elif 1900000000 > timestamp >= 0:  # 2030 > ts > 1970
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
    except Exception, e:
        print e


def friendly_date(timestamp):
    if isinstance(timestamp, (str, unicode, long, int)):
        return to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    else:
        return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

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
