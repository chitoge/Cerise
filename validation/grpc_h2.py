#!/usr/bin/env python3
"""Dependency-free HTTP/2 (h2c prior-knowledge) gRPC client for the Cerise file
server e2e test. Supports unary + server-streaming calls, a minimal protobuf
codec, and an HPACK decoder (static+dynamic table + Huffman, RFC 7541) so response
:status and the grpc-status trailer are decoded — no external packages.
"""
import socket, struct, time
from collections import deque

# ---- protobuf (proto3) mini codec -------------------------------------------
def pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pb_str(field: int, s: str) -> bytes:
    b = s.encode()
    return pb_varint((field << 3) | 2) + pb_varint(len(b)) + b


def pb_bytes(field: int, b: bytes) -> bytes:
    return pb_varint((field << 3) | 2) + pb_varint(len(b)) + b


def pb_uint(field: int, n: int) -> bytes:
    if n == 0:
        return b""  # proto3 default omitted
    return pb_varint((field << 3) | 0) + pb_varint(n)


def pb_bool(field: int, v: bool) -> bytes:
    return pb_uint(field, 1) if v else b""


def pb_decode(body: bytes) -> dict:
    """Decodes a flat protobuf message into {field_num: value} (varint->int,
    len-delimited->bytes). Repeated fields keep the last value."""
    fields, i = {}, 0
    while i < len(body):
        tag = body[i]; i += 1
        fnum, wt = tag >> 3, tag & 0x7
        if wt == 0:
            val, shift = 0, 0
            while True:
                b = body[i]; i += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            fields[fnum] = val
        elif wt == 2:
            ln, shift = 0, 0
            while True:
                b = body[i]; i += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            fields[fnum] = body[i:i + ln]
            i += ln
        else:
            raise ValueError(f"unsupported wire type {wt}")
    return fields


# ---- HPACK (RFC 7541) response decoder --------------------------------------
_STATIC = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"),
    (":status", "200"), (":status", "204"), (":status", "206"), (":status", "304"),
    (":status", "400"), (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""),
    ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
    ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""),
    ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""),
    ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
]

# HPACK Huffman table (RFC 7541 Appendix B): symbol -> (code, bit_length).
_HUFF = [
(0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),(0xfffffe5,28),(0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),(0x3ffffffc,30),(0xfffffe9,28),(0xfffffea,28),(0x3ffffffd,30),(0xfffffeb,28),(0xfffffec,28),(0xfffffed,28),(0xfffffee,28),(0xfffffef,28),(0xffffff0,28),(0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),(0xffffff4,28),(0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),(0xffffffa,28),(0xffffffb,28),
(0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),(0x1ff9,13),(0x15,6),(0xf8,8),(0x7fa,11),(0x3fa,10),(0x3fb,10),(0xf9,8),(0x7fb,11),(0xfa,8),(0x16,6),(0x17,6),(0x18,6),
(0x0,5),(0x1,5),(0x2,5),(0x19,6),(0x1a,6),(0x1b,6),(0x1c,6),(0x1d,6),(0x1e,6),(0x1f,6),(0x5c,7),(0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),(0x3fc,10),
(0x1ffa,13),(0x21,6),(0x5d,7),(0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),(0x63,7),(0x64,7),(0x65,7),(0x66,7),(0x67,7),(0x68,7),(0x69,7),(0x6a,7),
(0x6b,7),(0x6c,7),(0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),(0x72,7),(0xfc,8),(0x73,7),(0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffc,14),(0x22,6),
(0x7ffd,15),(0x3,5),(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),(0x27,6),(0x6,5),(0x74,7),(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),
(0x2b,6),(0x76,7),(0x2c,6),(0x8,5),(0x9,5),(0x2d,6),(0x77,7),(0x78,7),(0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),(0x3ffd,14),(0x1ffd,13),(0xffffffc,28),
(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),(0x3fffd3,22),(0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),(0x7fffda,23),(0x7fffdb,23),(0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),(0xffffeb,24),(0x7fffdf,23),
(0xffffec,24),(0xffffed,24),(0x3fffd7,22),(0x7fffe0,23),(0xffffee,24),(0x7fffe1,23),(0x7fffe2,23),(0x7fffe3,23),(0x7fffe4,23),(0x3fffd8,22),(0x7fffe5,23),(0x3fffd9,22),(0x7fffe6,23),(0x7fffe7,23),(0xffffef,24),(0x3fffda,22),
(0x7fffe8,23),(0x7fffe9,23),(0x3fffdb,22),(0x3fffdc,22),(0x7fffea,23),(0x7fffeb,23),(0x7fffec,23),(0xfffff0,24),(0x3fffdd,22),(0x7fffed,23),(0x3fffde,22),(0x7fffee,23),(0x7fffef,23),(0x3fffdf,22),(0x7ffff0,23),(0x3fffe0,22),
(0x3fffe1,22),(0x7ffff1,23),(0x1ffffe2,25),(0x3fffe2,22),(0x3fffe3,22),(0x3fffe4,22),(0x7ffff2,23),(0x3fffe5,22),(0x3fffe6,22),(0x7ffff3,23),(0x3ffffe0,26),(0x3ffffe1,26),(0x3fffe7,22),(0x1fffee,21),(0x7ffff4,23),(0x3fffe8,22),
(0x1ffffe3,25),(0x3ffffe2,26),(0x3ffffe3,26),(0x3ffffe4,26),(0x7ffffde,27),(0x7ffffdf,27),(0x3ffffe5,26),(0xfffff1,24),(0x1ffffe4,25),(0x3fffe9,22),(0x3ffffe6,26),(0x7ffffe0,27),(0x7ffffe1,27),(0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),
(0x1fffef,21),(0x3fffea,22),(0x3ffffe8,26),(0x1fffff0,25),(0x3ffffe9,26),(0x7ffffe3,27),(0x3ffffea,26),(0x3ffffeb,26),(0x1ffffe5,25),(0x3ffffec,26),(0x3ffffed,26),(0x7ffffe4,27),(0x1ffffe6,25),(0x7ffffe5,27),(0x1ffffe7,25),(0x1ffffe8,25),
(0x3ffffee,26),(0x7ffffe6,27),(0x1fffff1,25),(0x3ffffef,26),(0x3fffff0,26),(0x7ffffe7,27),(0x7ffffe8,27),(0xfffff3,24),(0x1fffff2,25),(0x7ffffe9,27),(0x3fffff1,26),(0x7ffffea,27),(0x7ffffeb,27),(0xffffffd,28),(0x3fffff2,26),(0x3fffff3,26),
(0x7ffffec,27),(0x1fffff3,25),(0x3fffff4,26),(0x1fffff4,25),(0x7ffffed,27),(0x3fffff5,26),(0x7ffffee,27),(0x7ffffef,27),(0x1fffff5,25),(0x3fffff6,26),(0x1fffff6,25),(0x1fffff7,25),(0x7fffff0,27),(0x1fffff8,25),(0x7fffff1,27),(0x3fffff7,26),
(0x3fffff8,26),(0x7fffff2,27),(0x1fffff9,25),(0x7fffff3,27),(0x7fffff4,27),(0x7fffff5,27),(0x3ffffe0,26),(0x3ffffe1,26),(0x1fffffa,25),(0x1ffffe0,25),(0x3fffff9,26),(0x1fffffb,25),(0x7fffff6,27),(0x3fffffa,26),(0x3fffffb,26),(0xffffffe,28),
(0x7fffff7,27),(0x7fffff8,27),(0x7fffff9,27),(0x7fffffa,27),(0x7fffffb,27),(0xffffffc,28),(0xfffffe1,28),(0xfffffe2b,32),(0x7fffffc,27),(0x3ffffff0,30),(0x3ffffff1,30),
]
# NOTE: entries above cover 0..255 in order; the last few very-rare symbols are
# unused by gRPC status headers. Build a (bits,code)->symbol decode map.
_HUFF_MAP = {}
for _sym, (_code, _blen) in enumerate(_HUFF):
    _HUFF_MAP[(_blen, _code)] = _sym


def _huff_decode(data: bytes) -> str:
    bits = 0
    nbits = 0
    out = bytearray()
    cur = 0
    curlen = 0
    for byte in data:
        for k in range(7, -1, -1):
            bit = (byte >> k) & 1
            cur = (cur << 1) | bit
            curlen += 1
            if (curlen, cur) in _HUFF_MAP:
                sym = _HUFF_MAP[(curlen, cur)]
                if sym == 256:
                    return out.decode("latin1")
                out.append(sym)
                cur = 0
                curlen = 0
    return out.decode("latin1")


class _HpackDecoder:
    def __init__(self):
        self.dyn = []  # most-recent-first

    def _read_int(self, data, i, prefix_bits):
        mask = (1 << prefix_bits) - 1
        val = data[i] & mask
        i += 1
        if val < mask:
            return val, i
        shift = 0
        while True:
            b = data[i]; i += 1
            val += (b & 0x7F) << shift
            if not (b & 0x80):
                return val, i
            shift += 7

    def _read_str(self, data, i):
        huff = (data[i] & 0x80) != 0
        length, i = self._read_int(data, i, 7)
        raw = data[i:i + length]
        i += length
        return (_huff_decode(raw) if huff else raw.decode("latin1")), i

    def _entry(self, index):
        if index <= 61:
            return _STATIC[index - 1]
        return self.dyn[index - 62]

    def decode(self, block: bytes) -> dict:
        headers = {}
        i = 0
        while i < len(block):
            b = block[i]
            if b & 0x80:  # indexed
                idx, i = self._read_int(block, i, 7)
                name, value = self._entry(idx)
            elif b & 0x40:  # literal with incremental indexing
                idx, i = self._read_int(block, i, 6)
                if idx == 0:
                    name, i = self._read_str(block, i)
                else:
                    name = self._entry(idx)[0]
                value, i = self._read_str(block, i)
                self.dyn.insert(0, (name, value))
            elif b & 0x20:  # dynamic table size update
                _sz, i = self._read_int(block, i, 5)
                continue
            else:  # literal without / never indexed
                idx, i = self._read_int(block, i, 4)
                if idx == 0:
                    name, i = self._read_str(block, i)
                else:
                    name = self._entry(idx)[0]
                value, i = self._read_str(block, i)
            headers[name] = value
        return headers


# ---- HTTP/2 framing ----------------------------------------------------------
_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _frame(ftype, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload


def _lit_hdr(name, value):
    n, v = name.encode(), value.encode()
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


class GrpcConn:
    """One HTTP/2 connection; issues gRPC calls sequentially on rising stream ids."""

    def __init__(self, host, port, timeout=20):
        self.host, self.port = host, port
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.next_sid = 1
        self.dec = _HpackDecoder()
        self.settings_acked = False
        self.send_conn_window = 65535
        self.send_stream_initial = 65535
        self.pending_frames = []
        self.sock.sendall(_PREFACE)
        # Advertise a large per-stream receive window (SETTINGS_INITIAL_WINDOW_SIZE) AND
        # enlarge the connection-level window, so large server-streaming responses (e.g.
        # a multi-chunk Read) aren't stalled by HTTP/2 flow control (default 65535).
        win = 8 * 1024 * 1024
        self.sock.sendall(_frame(0x4, 0, 0, struct.pack(">HI", 0x4, win)))  # SETTINGS
        self.sock.sendall(_frame(0x8, 0, 0, struct.pack(">I", win)))  # conn WINDOW_UPDATE

    def _flow_control(self, frame, stream_window=None):
        """Apply peer SETTINGS/WINDOW_UPDATE; return (handled, stream_window)."""
        ftype, flags, sid, payload = frame
        if ftype == 0x4:
            if not (flags & 0x1):
                old = self.send_stream_initial
                for i in range(0, len(payload), 6):
                    setting, value = struct.unpack(">HI", payload[i:i + 6])
                    if setting == 0x4:  # SETTINGS_INITIAL_WINDOW_SIZE
                        self.send_stream_initial = value
                if stream_window is not None:
                    stream_window += self.send_stream_initial - old
                if not self.settings_acked:
                    self.sock.sendall(_frame(0x4, 0x1, 0))
                    self.settings_acked = True
            return True, stream_window
        if ftype == 0x8 and len(payload) == 4:
            increment = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
            if sid == 0:
                self.send_conn_window += increment
                return True, stream_window
            if stream_window is not None:
                stream_window += increment
                return True, stream_window
        return False, stream_window

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _feed(self, deadline):
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                # The connection timeout bounds one idle recv, not the RPC.
                # Lifecycle calls may legitimately spend minutes serializing
                # a durable head without emitting an HTTP/2 frame. Keep
                # waiting until the caller's per-call deadline expires.
                continue
            if not chunk:
                return False
            self.buf += chunk
            return True
        return False

    def _next_frame(self, deadline):
        while True:
            if len(self.buf) >= 9:
                ln = struct.unpack(">I", b"\x00" + self.buf[:3])[0]
                if len(self.buf) >= 9 + ln:
                    ftype, flags = self.buf[3], self.buf[4]
                    sid = struct.unpack(">I", self.buf[5:9])[0] & 0x7FFFFFFF
                    payload = self.buf[9:9 + ln]
                    self.buf = self.buf[9 + ln:]
                    return ftype, flags, sid, payload
            if not self._feed(deadline):
                return None

    def _start_call(self, method, request_bytes, timeout):
        """Send one complete gRPC request and return its HTTP/2 stream id."""
        sid = self.next_sid
        self.next_sid += 2
        headers = (_lit_hdr(":method", "POST") + _lit_hdr(":scheme", "http")
                   + _lit_hdr(":path", method)
                   + _lit_hdr(":authority", f"{self.host}:{self.port}")
                   + _lit_hdr("content-type", "application/grpc")
                   + _lit_hdr("te", "trailers"))
        self.sock.sendall(_frame(0x1, 0x4, sid, headers))  # END_HEADERS
        grpc_msg = b"\x00" + struct.pack(">I", len(request_bytes)) + request_bytes
        # A gRPC message may span multiple DATA frames; each must fit within the peer's
        # SETTINGS_MAX_FRAME_SIZE (default 16384). Split at 16000; END_STREAM on the last.
        max_frame = 16000
        pos = 0
        send_deadline = time.time() + timeout
        stream_window = self.send_stream_initial
        while True:
            while self.send_conn_window == 0 or stream_window == 0:
                fr = self._next_frame(send_deadline)
                if fr is None:
                    raise TimeoutError("timed out waiting for HTTP/2 send window")
                handled, stream_window = self._flow_control(fr, stream_window)
                if not handled:
                    self.pending_frames.append(fr)
            count = min(max_frame, self.send_conn_window, stream_window,
                        len(grpc_msg) - pos)
            end = pos + count
            last = end >= len(grpc_msg)
            self.sock.sendall(_frame(0x0, 0x1 if last else 0, sid, grpc_msg[pos:end]))
            self.send_conn_window -= count
            stream_window -= count
            pos = end
            if last:
                break
        return sid

    def open_server_stream(
        self, method, request_bytes, timeout=30, max_message_bytes=None
    ):
        """Open a server stream on this otherwise-idle connection.

        The returned reader yields one raw protobuf message at a time.  This is
        intentionally small: it exists for long-lived event streams where
        ``call(..., streaming=True)`` cannot return until the server closes the
        stream.  Do not issue another call on this connection until the reader
        has been closed. ``max_message_bytes`` optionally rejects an oversized
        gRPC length prefix before its body is accumulated.
        """
        if max_message_bytes is not None and (
            isinstance(max_message_bytes, bool)
            or not isinstance(max_message_bytes, int)
            or max_message_bytes < 0
        ):
            raise ValueError("max_message_bytes must be a non-negative integer")
        sid = self._start_call(method, request_bytes, timeout)
        stream = GrpcServerStream(
            self, sid, max_message_bytes=max_message_bytes
        )
        stream.wait_ready(timeout)
        return stream

    def call(self, method, request_bytes, streaming=False, timeout=30):
        """Returns (messages: list[bytes], grpc_status: int, grpc_message: str)."""
        try:
            sid = self._start_call(method, request_bytes, timeout)
        except TimeoutError as error:
            return [], -1, str(error)

        deadline = time.time() + timeout
        data_bytes = bytearray()
        messages = []
        status = None
        gmessage = ""
        while True:
            fr = self.pending_frames.pop(0) if self.pending_frames else self._next_frame(deadline)
            if fr is None:
                break
            ftype, flags, fsid, payload = fr
            handled, _ = self._flow_control(fr)
            if handled:
                continue
            if fsid != sid:
                continue
            if ftype == 0x1:  # HEADERS (response headers or trailers)
                hdrs = self.dec.decode(payload)
                if "grpc-status" in hdrs:
                    status = int(hdrs["grpc-status"])
                    gmessage = hdrs.get("grpc-message", "")
                if flags & 0x1:  # END_STREAM (trailers)
                    break
            elif ftype == 0x0:  # DATA
                data_bytes.extend(payload)
                # split off any complete gRPC length-prefixed messages
                consumed = 0
                while len(data_bytes) - consumed >= 5:
                    mlen = struct.unpack(
                        ">I", data_bytes[consumed + 1:consumed + 5]
                    )[0]
                    if len(data_bytes) - consumed < 5 + mlen:
                        break
                    start = consumed + 5
                    messages.append(bytes(data_bytes[start:start + mlen]))
                    consumed += 5 + mlen
                if consumed:
                    del data_bytes[:consumed]
                if (flags & 0x1) and not streaming:
                    # unary: END_STREAM on DATA is unusual (trailers follow), keep reading
                    pass
        if status is None:
            status = 0 if messages else -1
        return messages, status, gmessage


class GrpcServerStream:
    """Incremental reader for a single server-streaming gRPC call."""

    def __init__(self, connection, stream_id, max_message_bytes=None):
        if max_message_bytes is not None and (
            isinstance(max_message_bytes, bool)
            or not isinstance(max_message_bytes, int)
            or max_message_bytes < 0
        ):
            raise ValueError("max_message_bytes must be a non-negative integer")
        self.connection = connection
        self.stream_id = stream_id
        self.max_message_bytes = max_message_bytes
        self.messages = deque()
        self.data_bytes = bytearray()
        self.ready = False
        self.ended = False
        self.grpc_status = None
        self.grpc_message = ""

    def _consume(self, deadline, stop_at_headers=False):
        while not self.messages and not self.ended:
            frame = (
                self.connection.pending_frames.pop(0)
                if self.connection.pending_frames
                else self.connection._next_frame(deadline)
            )
            if frame is None:
                raise TimeoutError("timed out waiting for gRPC server stream")
            ftype, flags, sid, payload = frame
            handled, _ = self.connection._flow_control(frame)
            if handled:
                continue
            if sid != self.stream_id:
                continue
            if ftype == 0x1:  # HEADERS (response headers or trailers)
                headers = self.connection.dec.decode(payload)
                self.ready = True
                if "grpc-status" in headers:
                    self.grpc_status = int(headers["grpc-status"])
                    self.grpc_message = headers.get("grpc-message", "")
                if flags & 0x1:
                    self.ended = True
                if stop_at_headers:
                    return
            elif ftype == 0x0:  # DATA
                # Replenish both receive windows as bytes are consumed so an
                # event/trace stream can outlive the initial 8 MiB allowance.
                if payload:
                    increment = struct.pack(">I", len(payload))
                    self.connection.sock.sendall(_frame(0x8, 0, 0, increment))
                    self.connection.sock.sendall(
                        _frame(0x8, 0, self.stream_id, increment)
                    )
                self.data_bytes.extend(payload)
                consumed = 0
                while len(self.data_bytes) - consumed >= 5:
                    if self.data_bytes[consumed] != 0:
                        raise ValueError("compressed gRPC messages are unsupported")
                    message_length = struct.unpack(
                        ">I",
                        self.data_bytes[consumed + 1:consumed + 5],
                    )[0]
                    if (
                        self.max_message_bytes is not None
                        and message_length > self.max_message_bytes
                    ):
                        raise ValueError(
                            "gRPC server stream message exceeds configured limit"
                        )
                    if (
                        len(self.data_bytes) - consumed
                        < 5 + message_length
                    ):
                        break
                    start = consumed + 5
                    self.messages.append(
                        bytes(self.data_bytes[start:start + message_length])
                    )
                    consumed += 5 + message_length
                if consumed:
                    del self.data_bytes[:consumed]
                if flags & 0x1:
                    self.ended = True
            elif ftype == 0x3:  # RST_STREAM
                self.ended = True
                if self.grpc_status is None:
                    self.grpc_status = -1
                    self.grpc_message = "peer reset the HTTP/2 stream"

    def wait_ready(self, timeout=30):
        deadline = time.time() + timeout
        while not self.ready and not self.ended:
            self._consume(deadline, stop_at_headers=True)
        if self.ended and self.grpc_status not in (None, 0):
            raise RuntimeError(
                f"gRPC stream failed with status {self.grpc_status}: "
                f"{self.grpc_message}"
            )
        return self

    def read(self, timeout=30):
        """Return the next raw protobuf message, or ``None`` at clean EOF."""
        if not self.messages and not self.ended:
            self._consume(time.time() + timeout)
        if self.messages:
            return self.messages.popleft()
        if self.grpc_status not in (None, 0):
            raise RuntimeError(
                f"gRPC stream failed with status {self.grpc_status}: "
                f"{self.grpc_message}"
            )
        return None

    def close(self):
        if self.ended:
            return
        try:
            # HTTP/2 CANCEL.  Closing the whole connection remains the safest
            # choice after cancellation because GrpcConn is intentionally
            # sequential and may still receive a late trailer for this stream.
            self.connection.sock.sendall(
                _frame(0x3, 0, self.stream_id, struct.pack(">I", 0x8))
            )
        except OSError:
            pass
        self.ended = True
