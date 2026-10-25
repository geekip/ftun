"""Exercise the synchronous control adapter through a real UDP Path."""
import socket
import subprocess
import sys
import threading


def main():
    errors = []
    received = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(5)

        def echo():
            try:
                for _ in range(4):
                    data, peer = server.recvfrom(65536)
                    received.append(data)
                    server.sendto(data, peer)
                data, peer = server.recvfrom(65536)
                received.append(data)
                assert data == b"burst", data
                for index in range(3):
                    server.sendto(bytes([index]), peer)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=echo)
        thread.start()
        try:
            result = subprocess.run([sys.argv[1], str(server.getsockname()[1])],
                                    capture_output=True, text=True, timeout=8)
        finally:
            thread.join(6)
        assert not thread.is_alive() and not errors, errors
        assert result.returncode == 0, result.stdout + result.stderr
        assert received == [b"abc", b"", b"oversize", b"next", b"burst"], received
    print("control datagram socket: packets, empty packet, size rejection, burst recovery, deadline passed")


if __name__ == "__main__":
    main()
