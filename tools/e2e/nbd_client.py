#!/usr/bin/env python3
"""A minimal NBD client for the loam-nbd gate: fixed-newstyle negotiation
and the transmission phase's READ, WRITE (optionally FUA), FLUSH and DISC.

usage: nbd_client.py <host:port> <command> [args...]

  size                         print the export's size in bytes
  write <offset> <file> [fua]  write the file's bytes at offset
  read <offset> <len> <file>   read len bytes at offset into file
  flush                        commit what was written
  script <file>                run one command per line on one connection
                               (write/read/flush as above), so a sequence
                               shares a session

Exits non-zero, naming the error, on any refusal.
"""

import socket
import struct
import sys

MAGIC = 0x4E42444D41474943  # "NBDMAGIC"
IHAVEOPT = 0x49484156454F5054
OPT_REPLY_MAGIC = 0x3E889045565A9
REQ_MAGIC = 0x25609513
REPLY_MAGIC = 0x67446698
OPT_GO = 7
OPT_EXPORT_NAME = 1
REP_ACK = 1
REP_INFO = 3
INFO_EXPORT = 0
CMD_READ, CMD_WRITE, CMD_DISC, CMD_FLUSH = 0, 1, 2, 3
FLAG_FUA = 1 << 0
FIXED_NEWSTYLE = 1 << 0
NO_ZEROES = 1 << 1


def recv_exact(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise SystemExit("nbd: the server closed the connection")
        out += chunk
    return out


class Nbd:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=60)
        magic, opt = struct.unpack(">QQ", recv_exact(self.s, 16))
        if magic != MAGIC or opt != IHAVEOPT:
            raise SystemExit("nbd: not a newstyle server")
        (hflags,) = struct.unpack(">H", recv_exact(self.s, 2))
        if not hflags & FIXED_NEWSTYLE:
            raise SystemExit("nbd: not fixed newstyle")
        self.s.sendall(struct.pack(">I", FIXED_NEWSTYLE | (hflags & NO_ZEROES)))
        # NBD_OPT_GO with the default export and no info requests.
        data = struct.pack(">I", 0) + struct.pack(">H", 0)
        self.s.sendall(struct.pack(">QII", IHAVEOPT, OPT_GO, len(data)) + data)
        self.size = None
        while True:
            magic, opt, rtype, rlen = struct.unpack(">QIII", recv_exact(self.s, 20))
            body = recv_exact(self.s, rlen)
            if magic != OPT_REPLY_MAGIC:
                raise SystemExit("nbd: bad option reply")
            if rtype == REP_INFO and len(body) >= 12 and struct.unpack(">H", body[:2])[0] == INFO_EXPORT:
                self.size, self.tflags = struct.unpack(">QH", body[2:12])
            elif rtype == REP_ACK:
                break
            elif rtype & (1 << 31):
                raise SystemExit(f"nbd: option refused, error {rtype:#x}")
        if self.size is None:
            raise SystemExit("nbd: no export size")
        self.handle = 0

    def cmd(self, kind, offset=0, length=0, data=b"", flags=0):
        self.handle += 1
        self.s.sendall(struct.pack(">IHHQQI", REQ_MAGIC, flags, kind, self.handle, offset, length) + data)
        if kind == CMD_DISC:
            return b""
        magic, error, handle = struct.unpack(">IIQ", recv_exact(self.s, 16))
        if magic != REPLY_MAGIC or handle != self.handle:
            raise SystemExit("nbd: bad reply")
        if error:
            raise SystemExit(f"nbd: error {error} on command {kind} at {offset}")
        return recv_exact(self.s, length) if kind == CMD_READ else b""

    def run(self, words):
        op = words[0]
        if op == "size":
            print(self.size)
        elif op == "write":
            data = open(words[2], "rb").read()
            fua = FLAG_FUA if len(words) > 3 and words[3] == "fua" else 0
            self.cmd(CMD_WRITE, int(words[1]), len(data), data, fua)
        elif op == "read":
            open(words[3], "wb").write(self.cmd(CMD_READ, int(words[1]), int(words[2])))
        elif op == "flush":
            self.cmd(CMD_FLUSH)
        else:
            raise SystemExit(f"nbd: unknown command {op}")

    def close(self):
        self.cmd(CMD_DISC)
        self.s.close()


def main():
    host, port = sys.argv[1].rsplit(":", 1)
    n = Nbd(host, int(port))
    if sys.argv[2] == "script":
        for line in open(sys.argv[3]):
            if line.strip():
                n.run(line.split())
    else:
        n.run(sys.argv[2:])
    n.close()


if __name__ == "__main__":
    main()
