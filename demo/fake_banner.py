"""Faux serveur SSH pour la démonstration : il envoie une bannière OpenSSH et n'autorise rien.

Usage : python3 demo/fake_banner.py "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1" 2222
"""

import socketserver
import sys


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.server.banner.encode("ascii") + b"\r\n")
        try:
            self.request.recv(1024)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with Server(("0.0.0.0", int(sys.argv[2])), Handler) as server:
        server.banner = sys.argv[1]
        server.serve_forever()
