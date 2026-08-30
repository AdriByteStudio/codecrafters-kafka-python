import socket
import struct


def main():
    server = socket.create_server(("localhost", 9092), reuse_port=True)
    conn, addr = server.accept()
    with conn:
        # Read the incoming request (we don't parse it for this stage)
        conn.recv(1024)

        # Send response: 4 bytes message_size (any value) + 4 bytes correlation_id (7)
        # Both are 32-bit signed integers in big-endian order
        response = struct.pack(">i", 0) + struct.pack(">i", 7)
        conn.sendall(response)


if __name__ == "__main__":
    main()
