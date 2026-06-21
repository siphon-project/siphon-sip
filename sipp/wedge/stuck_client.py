"""Non-reading TCP peer for the outbound-drain wedge regression.

Connects, floods OPTIONS, then NEVER reads the responses and holds the socket
open. This is the production trigger class (a peer that sends requests but stops
reading / abruptly closes — e.g. a toll-fraud scanner that never ACKs its 401s,
or a stream peer whose far end stalls). It backs up siphon's per-connection
outbound buffer (bounded mpsc + kernel send buffer).

Usage: stuck_client.py [host] [port] [count]
"""
import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
count = int(sys.argv[3]) if len(sys.argv) > 3 else 2000

# Shrink the receive buffer BEFORE connect so the advertised window closes fast.
# A default non-reading socket autotunes to several MB and would just absorb the
# replies; with a tiny window, siphon's writes block once its send buffer fills
# -> the per-connection channel fills -> a buggy drain stalls.
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
sock.connect((host, port))


def options(index):
    return (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/TCP {host}:6000;branch=z9hG4bK-stuck-{index}\r\n"
        f"From: <sip:stuck@{host}>;tag=stuck{index}\r\n"
        f"To: <sip:{host}>\r\n"
        f"Call-ID: stuck-{index}@{host}\r\n"
        f"CSeq: {index} OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


for index in range(1, count + 1):
    sock.sendall(options(index))
print(f"stuck_client: sent {count} OPTIONS, NOT reading; holding socket", flush=True)
time.sleep(180)  # hold the connection open so the buffer stays full
