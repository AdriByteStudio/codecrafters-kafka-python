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
        request_api_version = struct.unpack(">h", data[6:8])[0]
        correlation_id = struct.unpack(">i", data[8:12])[0]

        # ApiVersions response body: error_code (INT16)
        # error_code 35 = UNSUPPORTED_VERSION when the requested version is not supported.
        # We support ApiVersions versions 0-4.
        if 0 <= request_api_version <= 4:
            error_code = 0
        else:
            error_code = 35

        # Send response: message_size (4 bytes) + correlation_id (4 bytes) + error_code (2 bytes)
        response = struct.pack(">i", 0) + struct.pack(">i", correlation_id) + struct.pack(">h", error_code)
        conn.sendall(response)


if __name__ == "__main__":
    main()
