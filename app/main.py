import socket
import struct
import threading


def handle_request(data):
    # Parse request header v2:
    #   message_size:         INT32 (4 bytes)
    #   request_api_key:      INT16 (2 bytes)
    #   request_api_version:  INT16 (2 bytes)
    #   correlation_id:       INT32 (4 bytes)
    #   client_id:            NULLABLE_STRING (variable)
    #   TAG_BUFFER:           TAGGED_FIELDS (variable)
    request_api_version = struct.unpack(">h", data[6:8])[0]
    correlation_id = struct.unpack(">i", data[8:12])[0]

    # ApiVersions response body (v4):
    #   error_code:        INT16
    #   api_keys:          COMPACT_ARRAY of { api_key, min_version, max_version, TAG_BUFFER }
    #   throttle_time_ms:  INT32
    #   TAG_BUFFER:        TAGGED_FIELDS
    #
    # error_code 35 = UNSUPPORTED_VERSION when the requested version is not supported.
    # We support ApiVersions versions 0-4.
    if 0 <= request_api_version <= 4:
        error_code = 0
    else:
        error_code = 35

    # Build the api_keys array with entries for:
    #   - API key 18 (ApiVersions), versions 0-4
    #   - API key 75 (DescribeTopicPartitions), versions 0-0
    # COMPACT_ARRAY length is encoded as n + 1 (unsigned varint). With 2 elements, that's 3.
    api_keys = (
        bytes([3])  # array length: 2 elements -> 3
        + struct.pack(">h", 18)  # api_key: 18 (ApiVersions)
        + struct.pack(">h", 0)  # min_version: 0
        + struct.pack(">h", 4)  # max_version: 4
        + bytes([0])  # TAG_BUFFER: empty
        + struct.pack(">h", 75)  # api_key: 75 (DescribeTopicPartitions)
        + struct.pack(">h", 0)  # min_version: 0
        + struct.pack(">h", 0)  # max_version: 0
        + bytes([0])  # TAG_BUFFER: empty
    )

    # Build the response body
    body = (
        struct.pack(">h", error_code)  # error_code
        + api_keys  # api_keys array
        + struct.pack(">i", 0)  # throttle_time_ms: 0
        + bytes([0])  # TAG_BUFFER: empty
    )

    # Build the full response: message_size + header (correlation_id) + body
    header = struct.pack(">i", correlation_id)
    message_size = len(header) + len(body)
    return struct.pack(">i", message_size) + header + body


def handle_connection(conn):
    with conn:
        # Handle multiple sequential requests on the same connection.
        while True:
            data = conn.recv(1024)
            if not data:
                break  # client closed the connection
            response = handle_request(data)
            conn.sendall(response)


def main():
    server = socket.create_server(("localhost", 9092), reuse_port=True)
    while True:
        conn, addr = server.accept()
        # Handle each client connection in its own thread to support concurrency.
        thread = threading.Thread(target=handle_connection, args=(conn,))
        thread.start()


if __name__ == "__main__":
    main()
