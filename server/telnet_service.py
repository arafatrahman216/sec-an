"""
Tiny plaintext, unauthenticated TCP service for the pure TCP-hijack demo
(Design Report Phase 3 / Section 5: "a command is executed in the
Telnet-style session with no authentication"). Runs on the SERVER VM
(192.168.56.20).

No login, no TLS -- any established TCP connection to this port is treated
as trusted. That is the point: attacker/tcp_hijack.py never opens its own
connection here. It sniffs the client's already-open connection, reads the
live SEQ/ACK straight off the wire, and injects a forged segment into it.
This process's kernel TCP stack does the rest -- if the SEQ/ACK are correct,
the injected bytes are handed to this handler exactly like a normal line
of input, indistinguishable from the real client.

Run:
    python3 server/telnet_service.py --port 2323
"""

import argparse
import socketserver
import threading


class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip, client_port = self.client_address
        print(f"[telnet] connection from {client_ip}:{client_port}")
        self.request.sendall(b"welcome to lab-telnetd. type a command.\r\n> ")

        while True:
            data = self.request.recv(1024)
            if not data:
                break
            line = data.decode(errors="replace").strip()
            if not line:
                continue
            print(f"[telnet] {client_ip}:{client_port} sent: {line!r}")
            reply = f"OK: executed '{line}'\r\n> ".encode()
            self.request.sendall(reply)

        print(f"[telnet] connection from {client_ip}:{client_port} closed")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2323)
    args = parser.parse_args()

    server = ThreadingTCPServer((args.host, args.port), TelnetHandler)
    print(f"[telnet] unauthenticated TCP service listening on {args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[telnet] shutting down")
        server.shutdown()
