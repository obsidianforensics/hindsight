# -*- coding: utf-8 -*-
"""
Parser for Chromium Blink PageState binary format.

Supports:
- Versions 11-25: Legacy Pickle format
- Versions 26-33: Mojo serialization format

The PageState blob is found in the `page_state_raw` field of SNSS NavigationEntry records.
It encodes form data, scroll positions, POST bodies, file uploads, iframe state, and more.

Reference: third_party/blink/common/page_state/page_state_serialization.cc
"""

import dataclasses
import io
import logging
import struct
import typing

log = logging.getLogger(__name__)

MIN_VERSION = 11
MAX_LEGACY_VERSION = 25


class PageStateError(Exception):
    ...


class PickleReader:
    """Reads Chromium Pickle-encoded values from a byte buffer with 4-byte alignment."""

    def __init__(self, data: bytes):
        self._f = io.BytesIO(data)
        # First 4 bytes are the payload length
        self._payload_length = self._read_raw_uint32()
        if self._payload_length + 4 > len(data):
            raise PageStateError(
                f"Pickle payload length {self._payload_length} exceeds data length {len(data) - 4}")

    def _read_raw_uint32(self) -> int:
        raw = self._f.read(4)
        if len(raw) < 4:
            raise PageStateError("Unexpected end of pickle data")
        return struct.unpack("<I", raw)[0]

    def _align(self, length: int):
        remainder = length % 4
        if remainder:
            self._f.seek(4 - remainder, io.SEEK_CUR)

    def read_int32(self) -> int:
        raw = self._f.read(4)
        if len(raw) < 4:
            raise PageStateError("Unexpected end of pickle data reading int32")
        return struct.unpack("<i", raw)[0]

    def read_uint32(self) -> int:
        raw = self._f.read(4)
        if len(raw) < 4:
            raise PageStateError("Unexpected end of pickle data reading uint32")
        return struct.unpack("<I", raw)[0]

    def read_int64(self) -> int:
        raw = self._f.read(8)
        if len(raw) < 8:
            raise PageStateError("Unexpected end of pickle data reading int64")
        return struct.unpack("<q", raw)[0]

    def read_uint64(self) -> int:
        raw = self._f.read(8)
        if len(raw) < 8:
            raise PageStateError("Unexpected end of pickle data reading uint64")
        return struct.unpack("<Q", raw)[0]

    def read_bool(self) -> bool:
        return self.read_int32() != 0

    def read_real(self) -> float:
        """Read a double written via WriteData(8 bytes)."""
        length = self.read_int32()
        if length != 8:
            raise PageStateError(f"Expected real data length 8, got {length}")
        raw = self._f.read(8)
        if len(raw) < 8:
            raise PageStateError("Unexpected end of pickle data reading real")
        self._align(8)
        return struct.unpack("<d", raw)[0]

    def read_data(self) -> bytes:
        """Read a WriteData blob: int32 length + raw bytes + alignment."""
        length = self.read_int32()
        if length < 0:
            return b""
        raw = self._f.read(length)
        if len(raw) < length:
            raise PageStateError(f"Tried to read {length} bytes, got {len(raw)}")
        self._align(length)
        return raw

    def read_string16(self) -> typing.Optional[str]:
        """Read a nullable UTF-16LE string. Returns None if length is -1."""
        char_count = self.read_int32()
        if char_count == -1:
            return None
        byte_count = char_count * 2
        raw = self._f.read(byte_count)
        if len(raw) < byte_count:
            raise PageStateError(f"Tried to read {byte_count} string16 bytes, got {len(raw)}")
        self._align(byte_count)
        return raw.decode("utf-16-le", errors="replace")

    def read_string(self) -> typing.Optional[str]:
        """Read a nullable UTF-8 string. Returns None if length is -1."""
        length = self.read_int32()
        if length == -1:
            return None
        raw = self._f.read(length)
        if len(raw) < length:
            raise PageStateError(f"Tried to read {length} string bytes, got {len(raw)}")
        self._align(length)
        return raw.decode("utf-8", errors="replace")

    def read_string16_vector(self) -> typing.List[typing.Optional[str]]:
        """Read a vector of nullable String16 values."""
        count = self.read_int32()
        return [self.read_string16() for _ in range(count)]

    @property
    def remaining(self) -> int:
        pos = self._f.tell()
        self._f.seek(0, io.SEEK_END)
        end = self._f.tell()
        self._f.seek(pos)
        return end - pos


# --- Data classes ---

@dataclasses.dataclass
class FormElement:
    """A single form control from document_state."""
    name: str
    type: str
    values: typing.List[str]


@dataclasses.dataclass
class HttpBodyElement:
    """An element of an HTTP request body."""
    element_type: int  # 0=Data, 1=File, 2=Blob
    # Type 0 (Data)
    data: typing.Optional[bytes] = None
    # Type 1 (File)
    file_path: typing.Optional[str] = None
    file_offset: typing.Optional[int] = None
    file_length: typing.Optional[int] = None
    file_modification_time: typing.Optional[float] = None
    # Type 2 (Blob)
    blob_uuid: typing.Optional[str] = None

    @property
    def type_name(self) -> str:
        return {0: "data", 1: "file", 2: "blob"}.get(self.element_type, f"unknown({self.element_type})")


@dataclasses.dataclass
class HttpBody:
    """HTTP POST body associated with a navigation."""
    elements: typing.List[HttpBodyElement]
    identifier: int
    contains_passwords: typing.Optional[bool] = None
    http_content_type: typing.Optional[str] = None


@dataclasses.dataclass
class ViewState:
    """Scroll and zoom state for a frame."""
    visual_viewport_scroll_offset_x: typing.Optional[float] = None
    visual_viewport_scroll_offset_y: typing.Optional[float] = None
    scroll_offset_x: typing.Optional[int] = None
    scroll_offset_y: typing.Optional[int] = None
    page_scale_factor: typing.Optional[float] = None
    scroll_anchor_selector: typing.Optional[str] = None
    scroll_anchor_offset_x: typing.Optional[float] = None
    scroll_anchor_offset_y: typing.Optional[float] = None
    scroll_anchor_simhash: typing.Optional[int] = None


@dataclasses.dataclass
class FrameState:
    """State for a single frame (page or iframe)."""
    url: typing.Optional[str] = None
    target: typing.Optional[str] = None
    referrer: typing.Optional[str] = None
    referrer_policy: typing.Optional[int] = None
    document_state_raw: typing.Optional[typing.List[typing.Optional[str]]] = None
    form_elements: typing.Optional[typing.List[FormElement]] = None
    scroll_offset_x: typing.Optional[int] = None
    scroll_offset_y: typing.Optional[int] = None
    page_scale_factor: typing.Optional[float] = None
    visual_viewport_scroll_offset_x: typing.Optional[float] = None
    visual_viewport_scroll_offset_y: typing.Optional[float] = None
    scroll_restoration_type: typing.Optional[int] = None
    item_sequence_number: typing.Optional[int] = None
    document_sequence_number: typing.Optional[int] = None
    state_object: typing.Optional[str] = None
    http_body: typing.Optional[HttpBody] = None
    children: typing.Optional[typing.List["FrameState"]] = None
    view_state: typing.Optional[ViewState] = None
    initiator_origin: typing.Optional[str] = None
    navigation_api_key: typing.Optional[str] = None
    navigation_api_id: typing.Optional[str] = None
    navigation_api_state: typing.Optional[str] = None
    protect_url_in_navigation_api: typing.Optional[bool] = None
    initiator_base_url_string: typing.Optional[str] = None


@dataclasses.dataclass
class PageState:
    """Top-level parsed PageState."""
    version: int
    referenced_files: typing.Optional[typing.List[typing.Optional[str]]] = None
    top_frame: typing.Optional[FrameState] = None


# --- Parsing functions ---

def parse_document_state(raw_strings: typing.List[typing.Optional[str]]) -> typing.List[FormElement]:
    """Parse the document_state string vector into structured FormElement objects.

    Format: [signature, form_key, item_count, (name, type, value_size, values...)*]
    """
    elements = []
    if not raw_strings or len(raw_strings) < 3:
        return elements

    # raw_strings[0] is the signature, raw_strings[1] is the form key
    idx = 2
    try:
        item_count = int(raw_strings[idx] or "0")
        idx += 1

        for _ in range(item_count):
            if idx + 2 >= len(raw_strings):
                break
            name = raw_strings[idx] or ""
            idx += 1
            control_type = raw_strings[idx] or ""
            idx += 1
            value_size = int(raw_strings[idx] or "0")
            idx += 1

            values = []
            for _ in range(value_size):
                if idx < len(raw_strings):
                    values.append(raw_strings[idx] or "")
                    idx += 1
            elements.append(FormElement(name=name, type=control_type, values=values))
    except (ValueError, IndexError) as e:
        log.debug(f"Error parsing document_state: {e}")

    return elements


def _read_http_body_element(reader: PickleReader, version: int) -> HttpBodyElement:
    """Read a single HTTP body element."""
    element_type = reader.read_int32()

    if element_type == 0:  # kTypeData
        data = reader.read_data()
        return HttpBodyElement(element_type=0, data=data)

    elif element_type == 1:  # kTypeFile
        file_path = reader.read_string16()
        file_offset = reader.read_int64()
        file_length = reader.read_int64()
        file_modification_time = reader.read_real()
        return HttpBodyElement(
            element_type=1, file_path=file_path, file_offset=file_offset,
            file_length=file_length, file_modification_time=file_modification_time)

    elif element_type == 2:  # kTypeBlob
        if version >= 16:
            blob_uuid = reader.read_string()
        else:
            blob_uuid = reader.read_string16()  # was a GURL
        return HttpBodyElement(element_type=2, blob_uuid=blob_uuid)

    else:
        raise PageStateError(f"Unknown HTTP body element type: {element_type}")


def _read_http_body(reader: PickleReader, version: int) -> typing.Optional[HttpBody]:
    """Read the HTTP body block if present."""
    has_body = reader.read_bool()
    if not has_body:
        return None

    num_elements = reader.read_int32()
    elements = [_read_http_body_element(reader, version) for _ in range(num_elements)]
    identifier = reader.read_int64()

    contains_passwords = None
    if version >= 12:
        contains_passwords = reader.read_bool()

    return HttpBody(elements=elements, identifier=identifier, contains_passwords=contains_passwords)


def _read_frame_state(reader: PickleReader, version: int, is_top: bool) -> FrameState:
    """Read a single FrameState following the legacy field order (v11-25).

    Reference: ReadLegacyFrameState in page_state_serialization.cc
    """
    frame = FrameState()

    # 1. [v < 14 && !is_top] redundant version
    if version < 14 and not is_top:
        reader.read_int32()  # skip

    # 2. url
    frame.url = reader.read_string16()

    # 3. [v < 19] original_url_string (skip)
    if version < 19:
        reader.read_string16()

    # 4. target
    frame.target = reader.read_string16()

    # 5. [v < 25] unique-name upgrade for target - no extra read needed, just a rename

    # 6-9. [v < 15] parent, title, alternate_title, visited_time (skip)
    if version < 15:
        reader.read_string16()  # parent
        reader.read_string16()  # title
        reader.read_string16()  # alternate_title
        reader.read_real()      # visited_time

    # 10. [v >= 24] did_save_scroll_or_scale_state
    did_save_scroll = True  # default for v < 24
    if version >= 24:
        did_save_scroll = reader.read_bool()

    # 11. [if did_save_scroll] scroll_offset
    if did_save_scroll:
        frame.scroll_offset_x = reader.read_int32()
        frame.scroll_offset_y = reader.read_int32()

    # 12-13. [v < 15] target_item, visit_count (skip)
    if version < 15:
        reader.read_bool()   # target_item
        reader.read_int32()  # visit_count

    # 14. referrer
    frame.referrer = reader.read_string16()

    # 15. document_state
    frame.document_state_raw = reader.read_string16_vector()
    if frame.document_state_raw:
        frame.form_elements = parse_document_state(frame.document_state_raw)

    # 16. [if did_save_scroll] page_scale_factor
    if did_save_scroll:
        frame.page_scale_factor = reader.read_real()

    # 17. item_sequence_number
    frame.item_sequence_number = reader.read_int64()

    # 18. document_sequence_number
    frame.document_sequence_number = reader.read_int64()

    # 19. [v >= 21 && v < 23] frame_sequence_number (skip)
    if 21 <= version < 23:
        reader.read_int64()

    # 20. [v >= 17 && v < 19] target_frame_id (skip)
    if 17 <= version < 19:
        reader.read_int64()

    # 21. [v >= 18] referrer_policy
    if version >= 18:
        frame.referrer_policy = reader.read_int32()

    # 22. [v >= 20 && did_save_scroll] visual_viewport_scroll_offset
    if version >= 20 and did_save_scroll:
        frame.visual_viewport_scroll_offset_x = reader.read_real()
        frame.visual_viewport_scroll_offset_y = reader.read_real()

    # 23. [v >= 22] scroll_restoration_type
    if version >= 22:
        frame.scroll_restoration_type = reader.read_int32()

    # 24-25. state_object
    has_state_object = reader.read_bool()
    if has_state_object:
        frame.state_object = reader.read_string16()

    # 26-27. http_body
    body = _read_http_body(reader, version)

    # 28. http_content_type (always read, even if no body)
    http_content_type = reader.read_string16()
    if body:
        body.http_content_type = http_content_type
        frame.http_body = body

    # 29. [v < 14] unused referrer (skip)
    if version < 14:
        reader.read_string16()

    # 30-31. children
    num_children = reader.read_int32()
    if num_children > 0:
        frame.children = [
            _read_frame_state(reader, version, is_top=False)
            for _ in range(num_children)
        ]

    return frame


# --- Mojo binary deserialization (versions 26+) ---

class MojoReader:
    """Reads Mojo binary-serialized data from a byte buffer.

    All pointers are relative offsets from their own position.
    All structs have an 8-byte header (num_bytes, version).
    All allocations are 8-byte aligned.

    Reference: mojo/public/cpp/bindings/lib/ in Chromium source.
    """

    def __init__(self, data: bytes):
        self._data = data

    def _read_at(self, fmt: str, offset: int) -> tuple:
        size = struct.calcsize(fmt)
        if offset + size > len(self._data):
            raise PageStateError(f"Mojo read out of bounds at offset {offset} (need {size}, have {len(self._data) - offset})")
        return struct.unpack_from(fmt, self._data, offset)

    def read_uint32(self, offset: int) -> int:
        return self._read_at("<I", offset)[0]

    def read_int32(self, offset: int) -> int:
        return self._read_at("<i", offset)[0]

    def read_uint64(self, offset: int) -> int:
        return self._read_at("<Q", offset)[0]

    def read_int64(self, offset: int) -> int:
        return self._read_at("<q", offset)[0]

    def read_float(self, offset: int) -> float:
        return self._read_at("<f", offset)[0]

    def read_double(self, offset: int) -> float:
        return self._read_at("<d", offset)[0]

    def read_bool_byte(self, offset: int) -> bool:
        return self._read_at("<B", offset)[0] != 0

    def read_struct_header(self, offset: int) -> typing.Tuple[int, int]:
        """Returns (num_bytes, version)."""
        return self._read_at("<II", offset)

    def resolve_pointer(self, ptr_offset: int) -> typing.Optional[int]:
        """Resolve a relative pointer. Returns absolute offset or None if null."""
        rel = self.read_uint64(ptr_offset)
        if rel == 0:
            return None
        return ptr_offset + rel

    def read_array_header(self, offset: int) -> typing.Tuple[int, int]:
        """Returns (num_bytes, num_elements)."""
        return self._read_at("<II", offset)

    def read_utf8_string(self, struct_offset: int) -> typing.Optional[str]:
        """Read a mojo string (UTF-8 array) at the given struct offset.
        For plain `string` types, the pointer points directly to an array of chars."""
        arr_offset = self.resolve_pointer(struct_offset)
        if arr_offset is None:
            return None
        _, num_elements = self.read_array_header(arr_offset)
        data_start = arr_offset + 8
        raw = self._data[data_start:data_start + num_elements]
        return raw.decode("utf-8", errors="replace")

    def read_string16(self, ptr_offset: int) -> typing.Optional[str]:
        """Read a mojo_base.mojom.String16 struct: StructHeader + Pointer<Array<uint16>>."""
        struct_abs = self.resolve_pointer(ptr_offset)
        if struct_abs is None:
            return None
        # String16 struct: header(8) + pointer to array(8) = 16 bytes
        arr_abs = self.resolve_pointer(struct_abs + 8)
        if arr_abs is None:
            return None
        _, num_elements = self.read_array_header(arr_abs)
        data_start = arr_abs + 8
        byte_count = num_elements * 2
        raw = self._data[data_start:data_start + byte_count]
        return raw.decode("utf-16-le", errors="replace")

    def read_string16_array(self, ptr_offset: int) -> typing.Optional[typing.List[typing.Optional[str]]]:
        """Read array<mojo_base.mojom.String16?> -- array of nullable String16 pointers."""
        arr_abs = self.resolve_pointer(ptr_offset)
        if arr_abs is None:
            return None
        _, num_elements = self.read_array_header(arr_abs)
        result = []
        for i in range(num_elements):
            elem_ptr_offset = arr_abs + 8 + i * 8
            result.append(self.read_string16(elem_ptr_offset))
        return result


def _mojo_read_view_state(reader: MojoReader, ptr_offset: int) -> typing.Optional[ViewState]:
    """Read a ViewState struct from a pointer field."""
    struct_abs = reader.resolve_pointer(ptr_offset)
    if struct_abs is None:
        return None

    num_bytes, version = reader.read_struct_header(struct_abs)
    vs = ViewState()

    # @0: visual_viewport_scroll_offset -> Pointer<PointF>
    pointf_abs = reader.resolve_pointer(struct_abs + 8)
    if pointf_abs is not None:
        # PointF: header(8) + float x(4) + float y(4)
        vs.visual_viewport_scroll_offset_x = reader.read_float(pointf_abs + 8)
        vs.visual_viewport_scroll_offset_y = reader.read_float(pointf_abs + 12)

    # @1: scroll_offset -> Pointer<Point>
    point_abs = reader.resolve_pointer(struct_abs + 16)
    if point_abs is not None:
        # Point: header(8) + int32 x(4) + int32 y(4)
        vs.scroll_offset_x = reader.read_int32(point_abs + 8)
        vs.scroll_offset_y = reader.read_int32(point_abs + 12)

    # @2: page_scale_factor (double at offset 24)
    vs.page_scale_factor = reader.read_double(struct_abs + 24)

    # Version 1+ fields
    if version >= 1 and num_bytes >= 56:
        # @3: scroll_anchor_selector -> Pointer<String16>
        vs.scroll_anchor_selector = reader.read_string16(struct_abs + 32)

        # @4: scroll_anchor_offset -> Pointer<PointF> (nullable)
        pointf_abs2 = reader.resolve_pointer(struct_abs + 40)
        if pointf_abs2 is not None:
            vs.scroll_anchor_offset_x = reader.read_float(pointf_abs2 + 8)
            vs.scroll_anchor_offset_y = reader.read_float(pointf_abs2 + 12)

        # @5: scroll_anchor_simhash (uint64 at offset 48)
        vs.scroll_anchor_simhash = reader.read_uint64(struct_abs + 48)

    return vs


def _mojo_read_http_body(reader: MojoReader, ptr_offset: int) -> typing.Optional[HttpBody]:
    """Read an HttpBody struct from a pointer field."""
    struct_abs = reader.resolve_pointer(ptr_offset)
    if struct_abs is None:
        return None

    # HttpBody layout: header(8) + http_content_type ptr(8) + request_body ptr(8) + contains_passwords bool(1) + pad(7)
    http_content_type = reader.read_string16(struct_abs + 8)
    contains_passwords = reader.read_bool_byte(struct_abs + 24)

    # request_body -> Pointer<RequestBody>
    rb_abs = reader.resolve_pointer(struct_abs + 16)
    if rb_abs is None:
        if http_content_type:
            return HttpBody(elements=[], identifier=0, contains_passwords=contains_passwords,
                            http_content_type=http_content_type)
        return None

    # RequestBody layout: header(8) + elements ptr(8) + identifier int64(8) + contains_sensitive_info bool(1) + pad(7)
    identifier = reader.read_int64(rb_abs + 16)

    # elements -> Pointer<Array<Union(Element)>>
    elements_arr_abs = reader.resolve_pointer(rb_abs + 8)
    elements = []
    if elements_arr_abs is not None:
        _, num_elements = reader.read_array_header(elements_arr_abs)
        for i in range(num_elements):
            # Each union element is 16 bytes inline: size(4) + tag(4) + data(8)
            union_offset = elements_arr_abs + 8 + i * 16
            union_size = reader.read_uint32(union_offset)
            if union_size == 0:
                continue  # null union
            tag = reader.read_uint32(union_offset + 4)

            if tag == 0:  # blob_uuid (string, UTF-8)
                blob_abs = reader.resolve_pointer(union_offset + 8)
                blob_uuid = None
                if blob_abs is not None:
                    _, n = reader.read_array_header(blob_abs)
                    blob_uuid = reader._data[blob_abs + 8:blob_abs + 8 + n].decode("utf-8", errors="replace")
                elements.append(HttpBodyElement(element_type=2, blob_uuid=blob_uuid))

            elif tag == 1:  # bytes (array<uint8>)
                bytes_abs = reader.resolve_pointer(union_offset + 8)
                data = None
                if bytes_abs is not None:
                    _, n = reader.read_array_header(bytes_abs)
                    data = bytes(reader._data[bytes_abs + 8:bytes_abs + 8 + n])
                elements.append(HttpBodyElement(element_type=0, data=data))

            elif tag == 2:  # file (File struct)
                file_abs = reader.resolve_pointer(union_offset + 8)
                if file_abs is not None:
                    # File layout: header(8) + path ptr(8) + offset uint64(8) + length uint64(8) + mod_time ptr(8)
                    file_path = reader.read_string16(file_abs + 8)
                    file_offset = reader.read_uint64(file_abs + 16)
                    file_length = reader.read_uint64(file_abs + 24)
                    mod_time = None
                    time_abs = reader.resolve_pointer(file_abs + 32)
                    if time_abs is not None:
                        # Time: header(8) + int64 internal_value(8)
                        mod_time = reader.read_int64(time_abs + 8)
                    elements.append(HttpBodyElement(
                        element_type=1, file_path=file_path, file_offset=file_offset,
                        file_length=file_length, file_modification_time=mod_time))

    return HttpBody(elements=elements, identifier=identifier,
                    contains_passwords=contains_passwords, http_content_type=http_content_type)


def _mojo_read_frame_state(reader: MojoReader, ptr_offset: int) -> typing.Optional[FrameState]:
    """Read a FrameState struct from a pointer field."""
    struct_abs = reader.resolve_pointer(ptr_offset)
    if struct_abs is None:
        return None

    num_bytes, version = reader.read_struct_header(struct_abs)
    frame = FrameState()

    # FrameState packed layout (offsets relative to struct start):
    #   8:  url_string (Ptr)          @0
    #  16:  referrer (Ptr)            @1
    #  24:  target (Ptr)              @2
    #  32:  state_object (Ptr)        @3
    #  40:  document_state (Ptr)      @4
    #  48:  scroll_restoration_type (int32) @5
    #  52:  referrer_policy (int32)   @9  (packed into gap after @5)
    #  56:  view_state (Ptr)          @6
    #  64:  item_sequence_number (int64) @7
    #  72:  document_sequence_number (int64) @8
    #  80:  http_body (Ptr)           @10
    #  88:  children (Ptr)            @11
    #  96:  initiator_origin (Ptr)    @12 [v2+]
    # 104:  navigation_api_key (Ptr)  @13 [v3+]
    # 112:  navigation_api_id (Ptr)   @14 [v3+]
    # 120:  navigation_api_state (Ptr) @15 [v4+]
    # 128:  protect_url_in_navigation_api (bool) @16 [v5+]
    # 136:  initiator_base_url_string (Ptr) @17 [v6+]

    frame.url = reader.read_string16(struct_abs + 8)
    frame.referrer = reader.read_string16(struct_abs + 16)
    frame.target = reader.read_string16(struct_abs + 24)
    frame.state_object = reader.read_string16(struct_abs + 32)

    frame.document_state_raw = reader.read_string16_array(struct_abs + 40)
    if frame.document_state_raw:
        frame.form_elements = parse_document_state(frame.document_state_raw)

    frame.scroll_restoration_type = reader.read_int32(struct_abs + 48)
    frame.referrer_policy = reader.read_int32(struct_abs + 52)

    frame.view_state = _mojo_read_view_state(reader, struct_abs + 56)
    if frame.view_state:
        frame.scroll_offset_x = frame.view_state.scroll_offset_x
        frame.scroll_offset_y = frame.view_state.scroll_offset_y
        frame.page_scale_factor = frame.view_state.page_scale_factor
        frame.visual_viewport_scroll_offset_x = frame.view_state.visual_viewport_scroll_offset_x
        frame.visual_viewport_scroll_offset_y = frame.view_state.visual_viewport_scroll_offset_y

    frame.item_sequence_number = reader.read_int64(struct_abs + 64)
    frame.document_sequence_number = reader.read_int64(struct_abs + 72)

    frame.http_body = _mojo_read_http_body(reader, struct_abs + 80)

    # children -> Pointer<Array<Pointer<FrameState>>>
    children_arr_abs = reader.resolve_pointer(struct_abs + 88)
    if children_arr_abs is not None:
        _, num_children = reader.read_array_header(children_arr_abs)
        if num_children > 0:
            frame.children = []
            for i in range(num_children):
                child = _mojo_read_frame_state(reader, children_arr_abs + 8 + i * 8)
                if child:
                    frame.children.append(child)

    # Version 2+ fields
    if version >= 2 and num_bytes >= 104:
        frame.initiator_origin = reader.read_utf8_string(struct_abs + 96)

    if version >= 3 and num_bytes >= 120:
        frame.navigation_api_key = reader.read_string16(struct_abs + 104)
        frame.navigation_api_id = reader.read_string16(struct_abs + 112)

    if version >= 4 and num_bytes >= 128:
        frame.navigation_api_state = reader.read_string16(struct_abs + 120)

    if version >= 5 and num_bytes >= 136:
        frame.protect_url_in_navigation_api = reader.read_bool_byte(struct_abs + 128)

    if version >= 6 and num_bytes >= 144:
        frame.initiator_base_url_string = reader.read_string16(struct_abs + 136)

    return frame


def _parse_mojo_page_state(mojo_data: bytes) -> typing.Optional[PageState]:
    """Parse Mojo-serialized PageState (versions 26+)."""
    reader = MojoReader(mojo_data)

    # PageState layout: header(8) + referenced_files ptr(8) + top ptr(8) = 24 bytes
    num_bytes, version = reader.read_struct_header(0)

    state = PageState(version=0)  # mojo struct version, not pickle version
    state.referenced_files = reader.read_string16_array(8)
    state.top_frame = _mojo_read_frame_state(reader, 16)

    return state


def parse_page_state(raw: bytes) -> typing.Optional[PageState]:
    """Parse a PageState blob from the page_state_raw field of a NavigationEntry.

    Supports versions 11-25 (legacy Pickle format) and 26-33 (Mojo format).

    Args:
        raw: The raw bytes from NavigationEntry.page_state_raw

    Returns:
        PageState object, or None if the version is unsupported or data is invalid.
    """
    if not raw or len(raw) < 8:
        return None

    try:
        reader = PickleReader(raw)
    except PageStateError as e:
        log.warning(f"Failed to create PickleReader for PageState: {e}")
        return None

    try:
        version = reader.read_int32()

        # Special case: version -1 is just a URL string
        if version == -1:
            url = reader.read_string16()
            state = PageState(version=-1)
            state.top_frame = FrameState(url=url)
            return state

        if version < MIN_VERSION:
            log.debug(f"PageState version {version} is below minimum supported ({MIN_VERSION})")
            return None

        if version > MAX_LEGACY_VERSION:
            # Versions 26+: Mojo encoding
            mojo_data = reader.read_data()
            if not mojo_data:
                return PageState(version=version)
            try:
                state = _parse_mojo_page_state(mojo_data)
                if state:
                    state.version = version
                return state
            except PageStateError as e:
                log.warning(f"Error parsing Mojo PageState v{version}: {e}")
                return PageState(version=version)

        # Versions 11-25: legacy Pickle format
        state = PageState(version=version)

        # referenced_files (v14+)
        if version >= 14:
            state.referenced_files = reader.read_string16_vector()

        # top frame state
        state.top_frame = _read_frame_state(reader, version, is_top=True)

        return state

    except PageStateError as e:
        log.warning(f"Error parsing PageState: {e}")
        return None
    except Exception as e:
        log.warning(f"Unexpected error parsing PageState: {e}")
        return None
