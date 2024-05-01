"""
Copyright 2021, CCL Forensics
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import pathlib
import typing
import dataclasses
from types import MappingProxyType

from pyhindsight.lib.ccl_chrome_indexeddb import ccl_leveldb

__version__ = "0.2.1"
__description__ = "Module for reading the Chromium leveldb sessionstorage format"
__contact__ = "Alex Caithness"

# See: https://source.chromium.org/chromium/chromium/src/+/main:components/services/storage/dom_storage/session_storage_metadata.cc
# et al

_NAMESPACE_PREFIX = b"namespace-"
_MAP_ID_PREFIX = b"map-"

log = None


@dataclasses.dataclass(frozen=True)
class SessionStoreValue:
    value: str
    guid: typing.Optional[str]
    leveldb_sequence_number: int


class SessionStoreDb:
    # todo: get all grouped by namespace by host?
    # todo: get all grouped by namespace by host.key?
    # todo: consider refactoring to only getting metadata on first pass and everything else on demand?
    def __init__(self, in_dir: pathlib.Path):
        if not in_dir.is_dir():
            raise IOError("Input directory is not a directory")

        self._ldb = ccl_leveldb.RawLevelDb(in_dir)

        # If performance is a concern we should refactor this, but slow and steady for now

        # First collect the namespace (session/tab guid  + host) and map-ids together
        self._map_id_to_host = {}  # map_id: (guid, host)
        self._deleted_keys = set()

        for rec in self._ldb.iterate_records_raw():
            if rec.user_key.startswith(_NAMESPACE_PREFIX):
                if rec.user_key == _NAMESPACE_PREFIX:
                    continue  # bogus entry near the top usually
                try:
                    key = rec.user_key.decode("utf-8")
                except UnicodeDecodeError:
                    print(f"Invalid namespace key: {rec.user_key}")
                    continue

                split_key = key.split("-", 2)
                if len(split_key) != 3:
                    print(f"Invalid namespace key: {key}")
                    continue

                _, guid, host = split_key

                if not host:
                    continue  # TODO investigate why this happens

                # normalize host to lower just in case
                host = host.lower()
                guid_host_pair = guid, host

                if rec.state == ccl_leveldb.KeyState.Deleted:
                    self._deleted_keys.add(guid_host_pair)
                else:
                    try:
                        map_id = rec.value.decode("utf-8")
                    except UnicodeDecodeError:
                        print(f"Invalid namespace value: {key}")
                        continue

                    if not map_id:
                        continue  # TODO: investigate why this happens/do we want to keep the host around somewhere?

                    #if map_id in self._map_id_to_host_guid and self._map_id_to_host_guid[map_id] != guid_host_pair:
                    if map_id in self._map_id_to_host and self._map_id_to_host[map_id] != host:
                        print("Map ID Collision!")
                        print(f"map_id: {map_id}")
                        print(f"Old host: {self._map_id_to_host[map_id]}")
                        print(f"New host: {guid_host_pair}")
                        raise ValueError("map_id collision")
                    else:
                        self._map_id_to_host[map_id] = host

        # freeze stuff
        self._map_id_to_host = MappingProxyType(self._map_id_to_host)
        self._deleted_keys = frozenset(self._deleted_keys)

        self._host_lookup = {}  # {host: {ss_key: [SessionStoreValue, ...]}}
        self._orphans = []  #  list of tuples of key, value where we can't get the host
        for rec in self._ldb.iterate_records_raw():
            if rec.user_key.startswith(_MAP_ID_PREFIX):
                try:
                    key = rec.user_key.decode("utf-8")
                except UnicodeDecodeError:
                    print(f"Invalid map id key: {rec.user_key}")
                    continue

                if rec.state == ccl_leveldb.KeyState.Deleted:
                    continue  # TODO: do we want to keep the key around because the presence is important?

                split_key = key.split("-", 2)
                if len(split_key) != 3:
                    print(f"Invalid map id key: {key}")
                    continue

                _, map_id, ss_key = split_key

                if not split_key:
                    # TODO what does it mean when there is no key here?
                    #      The value will also be a single number (encoded utf-8)
                    continue

                try:
                    value = rec.value.decode("UTF-16-LE")
                except UnicodeDecodeError:
                    print(f"Error decoding value for {key}")
                    print(f"Raw Value: {rec.value}")
                    continue

                host = self._map_id_to_host.get(map_id)
                if not host:
                    self._orphans.append((ss_key, SessionStoreValue(value, None, rec.seq)))
                else:
                    self._host_lookup.setdefault(host, {})
                    self._host_lookup[host].setdefault(ss_key, [])
                    self._host_lookup[host][ss_key].append(SessionStoreValue(value, None, rec.seq))

    def __contains__(self, item: typing.Union[str, typing.Tuple[str, str]]) -> bool:
        """
        :param item: either the host as a str or a tuple of the host and a key (both str)
        :return: if item is a str, returns true if that host is present, if item is a tuple of (str, str), returns True
            if that host and key pair are present
        """

        if isinstance(item, str):
            return item in self._host_lookup
        elif isinstance(item, tuple) and len(item) == 2:
            host, key = item
            return host in self._host_lookup and key in self._host_lookup[host]
        else:
            raise TypeError("item must be a string or a tuple of (str, str)")

    def iter_hosts(self) -> typing.Iterable[str]:
        """
        :return: yields the hosts present in this SessionStorage
        """
        yield from self._host_lookup.keys()

    def get_all_for_host(self, host: str) -> dict[str, tuple[SessionStoreValue, ...]]:
        """
        :param host: the host (domain name) for the session storage
        :return: a dictionary where the keys are storage keys and the values are tuples of SessionStoreValue objects
            for that key. Multiple values may be returned as deleted or old values may be recovered.
        """
        if host not in self:
            return {}
        result_raw = dict(self._host_lookup[host])
        for ss_key in result_raw:
            result_raw[ss_key] = tuple(result_raw[ss_key])
        return result_raw

    def get_session_storage_key(self, host, key) -> tuple[SessionStoreValue, ...]:
        """
        :param host: the host (domain name) for the session storage
        :param key: the storage key
        :return: a tuple of SessionStoreValue matching the host and key. Multiple values may be returned as deleted or
            old values may be recovered.
        """
        if (host, key) not in self:
            return tuple()
        return tuple(self._host_lookup[host][key])

    def iter_orphans(self) -> typing.Iterable[tuple[str, SessionStoreValue]]:
        """
        Returns records which have been orphaned from their host (domain name) where it cannot be recovered. The keys
            may be named uniquely enough that the host may be inferred.
        :return: yields tuples of (session key, SessionStoreValue)
        """
        yield from self._orphans

    def __getitem__(self, item: typing.Union[str, typing.Tuple[str, str]]) -> typing.Union[
            dict[str, tuple[SessionStoreValue, ...]], tuple[SessionStoreValue, ...]]:
        if item not in self:
            raise KeyError(item)

        if isinstance(item, str):
            return self.get_all_for_host(item)
        elif isinstance(item, tuple) and len(item) == 2:
            return self.get_session_storage_key(*item)
        else:
            raise TypeError("item must be a string or a tuple of (str, str)")

    def __iter__(self) -> typing.Iterable[str]:
        """
        iterates the hosts present
        """
        return self.iter_hosts()

    def close(self):
        self._ldb.close()

    def __enter__(self) -> "SessionStoreDb":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def main(args):
    ldb_in_dir = pathlib.Path(args[0])
    ssdb = SessionStoreDb(ldb_in_dir)

    print("Hosts in db:")
    for host in ssdb:
        print(host)


if __name__ == '__main__':
    main(sys.argv[1:])
