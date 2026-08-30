import socket
import struct


def main():
    server = socket.create_server(("localhost", 9092), reuse_port=True)
    conn, addr = server.accept()
    with conn:
        # Read the incoming request
        data = conn.recv(1024)

        # Parse request header v2:
        #   message_size:         INT32 (4 bytes)
        #   request_api_key:      INT16 (2 bytes)
        #   request_api_version:  INT16 (2 bytes)
        #   correlation_id:       INT32 (4 bytes)
        #   client_id:            NULLABLE_STRING (variable)
        #   TAG_BUFFER:           TAGGED_FIELDS (variable)
        # The correlation_id is at offset 8 (after message_size and the two INT16 fields).
        correlation_id = struct.unpack(">i", data[8:12])[0]

        # Send response: 4 bytes message_size (any value) + 4 bytes correlation_id
        # Both are 32-bit signed integers in big-endian order
        response = struct.pack(">i", 0) + struct.pack(">i", correlation_id)
        conn.sendall(response)


if __name__ == "__main__":
    main()
