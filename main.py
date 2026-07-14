#!/usr/bin/env python3
"""
Tor P2P File-Sharing Node
=========================

A minimal peer-to-peer, gossip-style file transfer tool that runs entirely
over the Tor network using hidden services (.onion addresses).

WHAT THIS DOES
--------------
  * Listens locally for incoming Tor connections (a local port that your
    Tor hidden service forwards to - see SETUP below), so other peers can
    reach you.
  * At the same time, can dial OUT to other .onion peers through the local
    Tor SOCKS proxy (default 127.0.0.1:9050).
  * On every connection (incoming or outgoing) exchanges peer lists with
    the other side - a basic gossip protocol - so your known-peers set
    grows as the network introduces you around.
  * Lets you send a file to a peer you connect to, and automatically saves
    any file a peer sends you into a download folder.

------------------------------------------------------------------------
SETUP (one-time, outside Python)
------------------------------------------------------------------------
1. Install Tor:
       sudo apt install tor        # Debian/Ubuntu
       brew install tor            # macOS

2. Edit your torrc (usually /etc/tor/torrc, or /usr/local/etc/tor/torrc
   on macOS) and add a hidden service pointing at the port this script
   will listen on:

       HiddenServiceDir /var/lib/tor/p2p_node/
       HiddenServicePort 5000 127.0.0.1:5000

   This tells Tor: "anything that arrives at <your_onion>:5000 should be
   forwarded to 127.0.0.1:5000 on this machine" - which is exactly the
   local port this script binds to with --listen-port.

3. Make sure the SOCKS proxy is enabled (it is by default):
       SocksPort 9050

4. Restart Tor:
       sudo systemctl restart tor

5. Find your onion address:
       sudo cat /var/lib/tor/p2p_node/hostname
   Share this (e.g. abcdefgh...onion) with peers you want to connect with.

6. Install the Python SOCKS client library:
       pip install pysocks

------------------------------------------------------------------------
RUNNING
------------------------------------------------------------------------
Just listen and be ready to accept connections + files:

    python3 tor_p2p_node.py --listen-port 5000 --my-onion yourhash.onion

Listen AND connect out to a known peer, gossiping peer lists:

    python3 tor_p2p_node.py --listen-port 5000 --my-onion yourhash.onion \
        --connect peerhash.onion:5000

Connect out to a peer and immediately send them a file:

    python3 tor_p2p_node.py --listen-port 5000 --my-onion yourhash.onion \
        --connect peerhash.onion:5000 --send /path/to/file.zip

Received files land in ./downloads by default (--download-dir to change).

------------------------------------------------------------------------
SECURITY NOTE
------------------------------------------------------------------------
This is a minimal reference implementation for learning/experimentation:
  * Transport is already encrypted by Tor, but this script does no
    additional authentication - anyone who connects to your hidden
    service can gossip with you and send you files.
  * There's no message signing, so peer-list gossip could be spoofed by
    a malicious peer. Don't treat unauthenticated peer lists as trusted.
  * Received filenames are sanitized (path components stripped) but you
    should still only run this against peers you trust, and consider
    adding a max file size / allow-list before exposing it further.
"""

import argparse
import json
import os
import socket
import struct
import threading
import time

try:
    import socks  # PySocks
except ImportError:
    raise SystemExit("Missing dependency. Install it with: pip install pysocks")

CHUNK_SIZE = 64 * 1024
GOSSIP_INTERVAL_SECS = 30


# ---------------------------------------------------------------------------
# Simple length-prefixed JSON messaging helpers
# ---------------------------------------------------------------------------

def send_msg(sock, obj):
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(sock):
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    payload = recv_exact(sock, length)
    if payload is None:
        return None
    return json.loads(payload.decode("utf-8"))


# ---------------------------------------------------------------------------
# The node itself
# ---------------------------------------------------------------------------

class Node:
    def __init__(self, listen_port, my_onion, socks_host, socks_port, download_dir):
        self.listen_port = listen_port
        self.my_onion = my_onion
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.download_dir = download_dir
        self.self_addr = f"{my_onion}:{listen_port}" if my_onion else None

        self.peers = set()
        self.peers_lock = threading.Lock()

        self.active_conns = []
        self.active_conns_lock = threading.Lock()

        os.makedirs(self.download_dir, exist_ok=True)

    # -- peer bookkeeping -----------------------------------------------

    def add_peer(self, addr):
        if not addr or addr == self.self_addr:
            return
        with self.peers_lock:
            if addr not in self.peers:
                self.peers.add(addr)
                print(f"[gossip] learned about new peer: {addr}")

    def known_peers(self):
        with self.peers_lock:
            return list(self.peers)

    def _register_conn(self, sock):
        with self.active_conns_lock:
            self.active_conns.append(sock)

    def _unregister_conn(self, sock):
        with self.active_conns_lock:
            if sock in self.active_conns:
                self.active_conns.remove(sock)

    def _gossip_loop(self):
        """Periodically push our current peer list to everyone we're connected to."""
        while True:
            time.sleep(GOSSIP_INTERVAL_SECS)
            peers = self.known_peers()
            if not peers:
                continue
            with self.active_conns_lock:
                conns = list(self.active_conns)
            for sock in conns:
                try:
                    send_msg(sock, {"type": "peer_list", "peers": peers})
                except Exception:
                    pass  # connection likely closed; _handle_conn will clean it up

    # -- listening side (incoming Tor connections) -----------------------

    def start_listener(self):
        threading.Thread(target=self._listen_loop, daemon=True).start()

    def _listen_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.listen_port))
        srv.listen(20)
        print(f"[listen] waiting for incoming Tor connections on 127.0.0.1:{self.listen_port}")
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    # -- connecting side (outgoing, via Tor SOCKS) ------------------------

    def connect_to(self, onion_addr, send_file=None):
        host, port_str = onion_addr.rsplit(":", 1)
        port = int(port_str)
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, self.socks_host, self.socks_port)
        print(f"[connect] dialing {onion_addr} via Tor SOCKS {self.socks_host}:{self.socks_port} ...")
        s.connect((host, port))
        print(f"[connect] connected to {onion_addr}")
        threading.Thread(
            target=self._handle_conn, args=(s, onion_addr, send_file), daemon=True
        ).start()

    # -- shared connection handler ----------------------------------------

    def _handle_conn(self, sock, peer_addr=None, send_file=None):
        try:
            send_msg(sock, {"type": "hello", "onion": self.self_addr, "peers": self.known_peers()})
            hello = recv_msg(sock)
            if hello and hello.get("type") == "hello":
                their_addr = hello.get("onion")
                if their_addr:
                    self.add_peer(their_addr)
                    if peer_addr is None:
                        peer_addr = their_addr
                for p in hello.get("peers", []):
                    self.add_peer(p)

            self._register_conn(sock)

            if send_file:
                self._send_file(sock, send_file)

            while True:
                msg = recv_msg(sock)
                if msg is None:
                    break
                mtype = msg.get("type")
                if mtype == "file_meta":
                    self._receive_file(sock, msg)
                elif mtype == "peer_list":
                    for p in msg.get("peers", []):
                        self.add_peer(p)
                elif mtype == "hello":
                    pass  # already handled at handshake time
                else:
                    print(f"[recv] unknown message type from {peer_addr}: {mtype}")
        except Exception as e:
            print(f"[error] connection with {peer_addr} ended: {e}")
        finally:
            self._unregister_conn(sock)
            sock.close()

    # -- file transfer ------------------------------------------------------

    def _send_file(self, sock, filepath):
        if not os.path.isfile(filepath):
            print(f"[send] file not found: {filepath}")
            return
        size = os.path.getsize(filepath)
        name = os.path.basename(filepath)
        send_msg(sock, {"type": "file_meta", "name": name, "size": size})
        sent = 0
        with open(filepath, "rb") as f:
            while sent < size:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sock.sendall(chunk)
                sent += len(chunk)
        print(f"[send] sent '{name}' ({size} bytes)")

    def _receive_file(self, sock, meta):
        # Strip any path components from the reported name - never trust
        # a peer to hand you a safe path.
        name = os.path.basename(meta.get("name", "unnamed_file"))
        size = int(meta.get("size", 0))

        dest = os.path.join(self.download_dir, name)
        base, ext = os.path.splitext(name)
        counter = 1
        while os.path.exists(dest):
            dest = os.path.join(self.download_dir, f"{base}_{counter}{ext}")
            counter += 1

        print(f"[recv] incoming file '{name}' ({size} bytes) -> {dest}")
        remaining = size
        with open(dest, "wb") as f:
            while remaining > 0:
                chunk = sock.recv(min(CHUNK_SIZE, remaining))
                if not chunk:
                    print("[recv] connection closed before file fully received")
                    break
                f.write(chunk)
                remaining -= len(chunk)
        print(f"[recv] finished receiving '{name}' -> {dest}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Tor P2P gossip file-transfer node")
    parser.add_argument("--listen-port", type=int, required=True,
                         help="Local port to listen on (must match your HiddenServicePort target)")
    parser.add_argument("--my-onion", default=None,
                         help="Your own .onion address (without http://), used to announce yourself")
    parser.add_argument("--socks-host", default="127.0.0.1", help="Tor SOCKS proxy host (default 127.0.0.1)")
    parser.add_argument("--socks-port", type=int, default=9050, help="Tor SOCKS proxy port (default 9050)")
    parser.add_argument("--download-dir", default="./downloads", help="Where received files are saved")
    parser.add_argument("--connect", default=None,
                         help="Peer to dial out to, format: onionaddress.onion:port")
    parser.add_argument("--send", default=None,
                         help="Path to a file to send immediately after connecting (requires --connect)")
    args = parser.parse_args()

    if args.send and not args.connect:
        parser.error("--send requires --connect")

    node = Node(
        listen_port=args.listen_port,
        my_onion=args.my_onion,
        socks_host=args.socks_host,
        socks_port=args.socks_port,
        download_dir=args.download_dir,
    )

    # Listen for incoming connections (always on, this is the "server" side).
    node.start_listener()

    # Periodic gossip of our peer list to whoever we're connected to.
    threading.Thread(target=node._gossip_loop, daemon=True).start()

    # Optionally dial out to a peer right away (the "client" side, running
    # concurrently with the listener above).
    if args.connect:
        node.connect_to(args.connect, send_file=args.send)

    print("[node] running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[node] shutting down.")


if __name__ == "__main__":
    main()
