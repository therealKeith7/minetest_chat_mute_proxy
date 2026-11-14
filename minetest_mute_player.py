player = ''             # 'Bob' = one player, '@Discord' = all Discord relay, '' = mute nobody.
server = 'example.server.net' # Actual server shown in your Luanti screenshot.
server_port = 30000     # Actual server UDP port.
local_port = 31000      # Connect Luanti to 127.0.0.1 : 31000.
force_white_chat = True  # Replace incoming chat foreground colors with white.

"""Experimental single-player Luanti/Minetest UDP chat-filter proxy (v4).

Python 3 standard library only; no client modification or root permissions.

v4: Normalize foreground color escape sequences in decoded, unsplit,
server-to-client chat messages (including sender text) to opaque white. This
preserves all visible words and the existing configurable @discord muting.
Because Luanti foreground escape codes may be different lengths (e.g. named
colors), the UTF-16BE string counts are recalculated; the reliable sequence,
chat type, timestamp and every other packet are left intact. A message that
would exceed packet limits is passed through unchanged rather than truncated.

v3: Optional relay-wide muting with player = '@Discord'.
v2: Nonblocking UDP EAGAIN/EWOULDBLOCK/ENOBUFS packets are queued in order
instead of dropped or causing the proxy to exit.

Only recognized, unsplit chat packets are modified. Unknown, split, or malformed
packets pass through unchanged. Existing chat muting sets message type 0xFF;
this has been used in a live session but is not guaranteed by Luanti's API.
This is a one-client experimental proxy, not a security/privacy mechanism.
Displayed usernames are not authenticated identities. Test the change on your
own client; actual visual rendering can vary by Luanti version/server mods.
"""

import errno
import re
import selectors
import socket
import struct
import sys
import time
from collections import deque

PROTOCOL_ID = b'\x4f\x45\x74\x03'
TOCLIENT_CHAT_MESSAGE = 0x002F
INVALID_CHAT_TYPE = 0xFF
COLOR_CODES = re.compile(r'\x1b\([^)]{0,80}\)')
FOREGROUND_COLOR = re.compile(r'\x1b\(c@[^)\x1b]{1,80}\)')
WHITE_ESCAPE = '\x1b(c@#ffffff)'
MAX_UDP_PAYLOAD = 65507  # Conservative IPv4 UDP payload maximum.
CHAT_PREFIX = re.compile(r'^\s*(?:<([^<>\r\n]{1,64})>|([^:\r\n]{1,64}):)\s')

# The high-water mark pauses reading from the corresponding source rather
# than dropping queued packets. A hard ceiling catches unexpected growth.
HIGH_WATER_BYTES = 2 * 1024 * 1024
HARD_LIMIT_BYTES = 8 * 1024 * 1024
BATCH_LIMIT = 64
TRANSIENT_ERRNOS = {errno.EAGAIN, errno.EWOULDBLOCK, errno.ENOBUFS, errno.EINTR}


def sender_from_text(sender_field, message):
    # Keep the relay suffix: <Kiwi@Discord> identifies both Kiwi and Discord.
    # A server may colorize sender_field itself; ignore those codes for mute matching.
    clean_sender = COLOR_CODES.sub('', sender_field).strip()
    if clean_sender:
        return clean_sender
    stripped = COLOR_CODES.sub('', message)
    m = CHAT_PREFIX.match(stripped)
    if not m:
        return None
    return (m.group(1) or m.group(2)).strip() or None


def sender_matches_filter(displayed_sender, filter_value):
    # Name 'Bob' matches 'Bob' or 'Bob@Discord'.
    # Source '@Discord' matches any 'name@Discord' but not message-body text.
    # 'Bob@Discord' matches that specific sender/source combination.
    target = filter_value.strip().casefold()
    name = displayed_sender.strip().casefold()
    if not target or not name:
        return False
    base, sep, source = name.rpartition('@')
    if target.startswith('@'):
        return bool(sep and base and source and ('@' + source) == target)
    if '@' in target:
        return name == target
    return (base if sep and base else name) == target


def white_foreground(text):
    """Convert Luanti foreground escapes to white without dropping any words.

    Non-foreground escapes, e.g. translations or backgrounds, are unchanged.
    The selected RGB is opaque white to keep dark-on-dark/invisible colors
    legible; named, short-hex and alpha-coded colors are handled the same way.
    """
    return FOREGROUND_COLOR.sub(WHITE_ESCAPE, text)


def inspect_and_filter(datagram, muted_name, whiten=force_white_chat):
    """Return (rewritten_datagram, muted, is_chat, whitened).

    Reliable packet sequence and ordering remain intact. Only recognized,
    unsplit server->client chat command sender/message fields are decoded.
    Every other field and non-chat datagram is preserved byte-for-byte.
    """
    if len(datagram) < 10 or not datagram.startswith(PROTOCOL_ID):
        return datagram, False, False, False
    p = 7  # [protocol-id:4][sender peer:2][channel:1]
    if datagram[p] == 3:  # reliable [type:1][seq:2][inner packet]
        p += 3
    if len(datagram) < p + 3 or datagram[p] != 1:  # ORIGINAL only
        return datagram, False, False, False
    cmd = struct.unpack_from('!H', datagram, p + 1)[0]
    if cmd != TOCLIENT_CHAT_MESSAGE:
        return datagram, False, False, False
    p += 3  # [version:1][message type:1][UTF-16BE sender:...]
    try:
        if len(datagram) < p + 6 or datagram[p] != 1:
            return datagram, False, True, False
        msg_type = datagram[p + 1]
        if msg_type >= 3:
            return datagram, False, True, False
        n = struct.unpack_from('!H', datagram, p + 2)[0]
        name_start = p + 4
        name_end = name_start + 2 * n
        if name_end + 2 > len(datagram):
            return datagram, False, True, False
        sender_field = datagram[name_start:name_end].decode('utf-16-be')
        m = struct.unpack_from('!H', datagram, name_end)[0]
        message_start = name_end + 2
        message_end = message_start + m * 2
        if message_end + 8 > len(datagram):
            return datagram, False, True, False
        message = datagram[message_start:message_end].decode('utf-16-be')
        sender_name = sender_from_text(sender_field, message)
    except (IndexError, struct.error, UnicodeError):
        return datagram, False, True, False

    if muted_name and sender_name is not None and sender_matches_filter(sender_name, muted_name):
        # Keep v3's proven mute behavior: same packet length, same sequence.
        rewritten = bytearray(datagram)
        rewritten[p + 1] = INVALID_CHAT_TYPE
        return bytes(rewritten), True, True, False

    if not whiten:
        return datagram, False, True, False

    clean_sender = white_foreground(sender_field)
    clean_message = white_foreground(message)
    if clean_sender == sender_field and clean_message == message:
        return datagram, False, True, False

    # UTF-16 protocol counts are CODE UNITS, not Python code points; this
    # distinction matters for emoji and other supplementary characters.
    sender_bytes = clean_sender.encode('utf-16-be')
    message_bytes = clean_message.encode('utf-16-be')
    sender_units = len(sender_bytes) // 2
    message_units = len(message_bytes) // 2
    if sender_units > 65535 or message_units > 65535:
        return datagram, False, True, False

    # Rebuild only two length-prefixed strings; leave timestamp, reliable
    # sequence and any trailing payload unchanged. Never modify other packet
    # types or arbitrary bytes that happen to resemble a color escape.
    rewritten = (datagram[:p + 2] + struct.pack('!H', sender_units) +
                 sender_bytes + struct.pack('!H', message_units) +
                 message_bytes + datagram[message_end:])
    if len(rewritten) > MAX_UDP_PAYLOAD:
        return datagram, False, True, False
    return rewritten, False, True, True


def set_socket_buffers(sock):
    for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, option, 2 * 1024 * 1024)
        except OSError:
            pass


def make_upstream(hostname, port):
    last_error = None
    addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_DGRAM)
    for family, socktype, proto, _, address in addresses:
        upstream = socket.socket(family, socktype, proto)
        try:
            set_socket_buffers(upstream)
            upstream.connect(address)
            upstream.setblocking(False)
            return upstream
        except OSError as exc:
            last_error = exc
            upstream.close()
    raise OSError(f'Unable to open UDP socket to {hostname}:{port}: {last_error}')


class LocalProxy:
    def __init__(self):
        self.local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        set_socket_buffers(self.local)
        self.local.bind(('127.0.0.1', local_port))
        self.local.setblocking(False)
        self.remote = None
        self.client = None
        self.selector = selectors.DefaultSelector()
        self.to_remote = deque()  # packets from game => server
        self.to_local = deque()  # (packet, client address) from server => game
        self.to_remote_bytes = 0
        self.to_local_bytes = 0
        self.packets_in = 0
        self.packets_out = 0
        self.chat_seen = 0
        self.muted = 0
        self.whitened = 0
        self.transient_sends = 0
        self.max_queued_bytes = 0
        self.last_status = time.monotonic()
        self.refresh_interest()

    def _listen(self, sock, tag, events):
        if sock is None:
            return
        try:
            self.selector.get_key(sock)
        except KeyError:
            if events:
                self.selector.register(sock, events, tag)
        else:
            if events:
                self.selector.modify(sock, events, tag)
            else:
                self.selector.unregister(sock)

    def refresh_interest(self):
        # We stop reading from a source when its destination queue grows. The
        # destination still watches WRITE so the backlog can drain.
        local_events = 0
        if self.to_remote_bytes < HIGH_WATER_BYTES:
            local_events |= selectors.EVENT_READ
        if self.to_local:
            local_events |= selectors.EVENT_WRITE
        self._listen(self.local, 'local', local_events)
        if self.remote is not None:
            remote_events = 0
            if self.to_local_bytes < HIGH_WATER_BYTES:
                remote_events |= selectors.EVENT_READ
            if self.to_remote:
                remote_events |= selectors.EVENT_WRITE
            self._listen(self.remote, 'remote', remote_events)

    def new_session(self, addr):
        if self.remote is not None:
            self._listen(self.remote, 'remote', 0)
            self.remote.close()
        self.remote = make_upstream(server, server_port)
        self.client = addr
        self.to_remote.clear()
        self.to_local.clear()
        self.to_remote_bytes = 0
        self.to_local_bytes = 0
        self.refresh_interest()
        print('Game session connected to proxy.', flush=True)

    def _send_remote(self, packet):
        if self.remote is None:
            return False
        try:
            written = self.remote.send(packet)
        except OSError as exc:
            if exc.errno in TRANSIENT_ERRNOS:
                self.transient_sends += 1
                return False
            raise
        if written != len(packet):
            raise OSError(f'Unexpected partial UDP write to server ({written}/{len(packet)})')
        return True

    def _send_local(self, packet, addr):
        try:
            written = self.local.sendto(packet, addr)
        except OSError as exc:
            if exc.errno in TRANSIENT_ERRNOS:
                self.transient_sends += 1
                return False
            raise
        if written != len(packet):
            raise OSError(f'Unexpected partial UDP write to game ({written}/{len(packet)})')
        return True

    def _record_queue(self):
        total = self.to_remote_bytes + self.to_local_bytes
        self.max_queued_bytes = max(total, self.max_queued_bytes)
        if total > HARD_LIMIT_BYTES:
            raise OSError('Proxy queue exceeded 8 MiB; stopped rather than silently dropping UDP traffic')

    def forward_remote(self, packet):
        # Once packets are queued, subsequent packets MUST join that queue
        # rather than jumping ahead of them when the socket becomes writable.
        if self.to_remote or not self._send_remote(packet):
            self.to_remote.append(packet)
            self.to_remote_bytes += len(packet)
            self._record_queue()
        self.refresh_interest()

    def forward_local(self, packet, addr):
        if self.to_local or not self._send_local(packet, addr):
            self.to_local.append((packet, addr))
            self.to_local_bytes += len(packet)
            self._record_queue()
        self.refresh_interest()

    def flush_remote(self):
        for _ in range(BATCH_LIMIT):
            if not self.to_remote:
                break
            packet = self.to_remote[0]
            if not self._send_remote(packet):
                break
            self.to_remote.popleft()
            self.to_remote_bytes -= len(packet)
        self.refresh_interest()

    def flush_local(self):
        for _ in range(BATCH_LIMIT):
            if not self.to_local:
                break
            packet, addr = self.to_local[0]
            if not self._send_local(packet, addr):
                break
            self.to_local.popleft()
            self.to_local_bytes -= len(packet)
        self.refresh_interest()

    def receive_local(self):
        for _ in range(BATCH_LIMIT):
            try:
                packet, addr = self.local.recvfrom(65535)
            except OSError as exc:
                if exc.errno in TRANSIENT_ERRNOS:
                    break
                raise
            if addr[0] != '127.0.0.1':
                continue
            if self.client != addr:
                self.new_session(addr)
            self.forward_remote(packet)
            self.packets_out += 1
            if self.to_remote_bytes >= HIGH_WATER_BYTES:
                break

    def receive_remote(self):
        for _ in range(BATCH_LIMIT):
            try:
                packet = self.remote.recv(65535)
            except OSError as exc:
                if exc.errno in TRANSIENT_ERRNOS:
                    break
                raise
            self.packets_in += 1
            packet, muted, chat, whitened = inspect_and_filter(
                packet, player.strip(), force_white_chat)
            if chat:
                self.chat_seen += 1
            if whitened:
                self.whitened += 1
            if muted:
                self.muted += 1
                print(f'Muted one message from {player} (total {self.muted}).', flush=True)
            self.forward_local(packet, self.client)
            if self.to_local_bytes >= HIGH_WATER_BYTES:
                break

    def run(self):
        print(f'Local proxy listening on 127.0.0.1:{local_port}', flush=True)
        print(f'Real server: {server}:{server_port}', flush=True)
        print(f'Muting: {player!r}' if player else 'Muting disabled (player is empty).', flush=True)
        print(f'Force incoming chat foreground to white: {force_white_chat}', flush=True)
        print(f'Connect Luanti to 127.0.0.1, port {local_port}. Press Ctrl+C to stop.', flush=True)
        try:
            while True:
                for key, mask in self.selector.select(timeout=1):
                    # Ignore a stale key if a different client caused a reset.
                    if key.data == 'local':
                        if mask & selectors.EVENT_WRITE:
                            self.flush_local()
                        if mask & selectors.EVENT_READ:
                            self.receive_local()
                    elif key.fileobj is self.remote:
                        if mask & selectors.EVENT_WRITE:
                            self.flush_remote()
                        if mask & selectors.EVENT_READ:
                            self.receive_remote()
                now = time.monotonic()
                if now - self.last_status >= 10:
                    print(f'Traffic: server->client={self.packets_in}, '
                          f'client->server={self.packets_out}, '
                          f'pending={self.to_remote_bytes + self.to_local_bytes} bytes, '
                          f'transient sends={self.transient_sends}, muted={self.muted}, '
                          f'white={self.whitened}', flush=True)
                    self.last_status = now
        except KeyboardInterrupt:
            print('\nStopped by user.', flush=True)
        finally:
            print(f'Summary: incoming={self.packets_in}, outgoing={self.packets_out}, '
                  f'chat={self.chat_seen}, muted={self.muted}, white={self.whitened}, '
                  f'temporary send stalls={self.transient_sends}, '
                  f'peak pending={self.max_queued_bytes} bytes', flush=True)
            self.selector.close()
            self.local.close()
            if self.remote is not None:
                self.remote.close()


def main():
    if not server.strip():
        print('Set server = ... at the top of the file.')
        return 2
    if not (1 <= local_port <= 65535 and 1 <= server_port <= 65535):
        print('Ports must be between 1 and 65535.')
        return 2
    if server.strip().lower() in ('127.0.0.1', 'localhost', '::1') and local_port == server_port:
        print('Server and proxy cannot share the same local port.')
        return 2
    try:
        LocalProxy().run()
        return 0
    except OSError as exc:
        print(f'Network error: {exc}', file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
