"""Stand-in for `wacli sync --follow`: holds the store lock and answers delegated sends.

It speaks wacli's delegate protocol (one JSON request, one JSON reply, over
`<store>/.send.sock`) and never talks to WhatsApp. Every request is appended to
`<store>/delegate-requests.jsonl` so tests can assert exactly what wacli asked for.

Usage: fake_daemon.py STORE_DIR REPLY_JSON
"""

import fcntl
import os
import signal
import socket
import sys

store, reply = sys.argv[1], sys.argv[2]
os.chdir(store)  # bind by relative path: deep temp dirs exceed the 108-byte socket path limit

lock = open("LOCK", "a+")  # noqa: SIM115 - held for the process lifetime
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
lock.seek(0)
lock.truncate()
lock.write(f"pid={os.getpid()}\n")
lock.flush()

if os.path.exists(".send.sock"):
    os.unlink(".send.sock")
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(".send.sock")
os.chmod(".send.sock", 0o600)
server.listen(4)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
open("daemon-ready", "w").close()

while True:
    conn, _ = server.accept()
    with conn:
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        if not buf.strip():
            continue
        with open("delegate-requests.jsonl", "a") as fh:
            fh.write(buf.decode().strip() + "\n")
        conn.sendall(reply.encode() + b"\n")
