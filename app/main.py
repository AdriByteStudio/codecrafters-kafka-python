import socket
import struct
import threading


def read_varint(data, offset):
    """Read an unsigned varint from data at offset. Returns (value, new_offset)."""
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return value, offset


def skip_tag_buffer(data, offset):
    """Skip a TAGGED_FIELDS structure. Returns new_offset."""
    num_fields, offset = read_varint(data, offset)
    for _ in range(num_fields):
        _, offset = read_varint(data, offset)  # tag
        size, offset = read_varint(data, offset)  # size
        offset += size
    return offset


def parse_request_header(data):
    """Parse request header v2.

    Returns (api_key, api_version, correlation_id, body_offset).
    """
    offset = 0
    offset += 4  # message_size: INT32
    api_key = struct.unpack(">h", data[offset:offset + 2])[0]
    offset += 2
    api_version = struct.unpack(">h", data[offset:offset + 2])[0]
    offset += 2
    correlation_id = struct.unpack(">i", data[offset:offset + 4])[0]
    offset += 4
    # client_id: NULLABLE_STRING (INT16 length + bytes)
    client_id_len = struct.unpack(">h", data[offset:offset + 2])[0]
    offset += 2
    if client_id_len >= 0:
        offset += client_id_len
    # TAG_BUFFER: TAGGED_FIELDS
    offset = skip_tag_buffer(data, offset)
    return api_key, api_version, correlation_id, offset


def build_api_versions_response(correlation_id, request_api_version):
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


def build_describe_topic_partitions_response(data, correlation_id, body_offset):
    # Parse the request body to extract the topic name.
    # DescribeTopicPartitions request (v0) body:
    #   topics: COMPACT_ARRAY of { topic_name: COMPACT_STRING, TAG_BUFFER }
    #   TAG_BUFFER
    offset = body_offset
    num_topics, offset = read_varint(data, offset)  # topics array length (n + 1)
    num_topics -= 1
    # Read the first topic name (COMPACT_STRING: length is n + 1)
    name_len, offset = read_varint(data, offset)
    name_len -= 1
    topic_name = data[offset:offset + name_len]

    # Build the DescribeTopicPartitions response (v0) for an unknown topic.
    # Response header v1: correlation_id (INT32) + TAG_BUFFER (empty)
    header = struct.pack(">i", correlation_id) + bytes([0])

    # Response body:
    #   throttle_time_ms:        INT32 (0)
    #   topics:                  COMPACT_ARRAY
    #     error_code:            INT16 (3 = UNKNOWN_TOPIC_OR_PARTITION)
    #     topic_name:            COMPACT_STRING
    #     topic_id:              UUID (16 bytes, all zeros)
    #     is_internal:           BOOLEAN (false)
    #     partitions:            COMPACT_ARRAY (empty)
    #     topic_authorized_operations: INT32 (0)
    #     TAG_BUFFER:            empty
    #   next_cursor:             NULLABLE_INT8 (-1 = null)
    #   TAG_BUFFER:              empty
    topic = (
        struct.pack(">h", 3)  # error_code: 3 (UNKNOWN_TOPIC_OR_PARTITION)
        + bytes([len(topic_name) + 1])  # topic_name length (compact string: n + 1)
        + topic_name  # topic_name
        + bytes(16)  # topic_id: all zeros
        + bytes([0])  # is_internal: false
        + bytes([1])  # partitions array: 0 elements -> 1
        + struct.pack(">i", 0)  # topic_authorized_operations: 0
        + bytes([0])  # TAG_BUFFER: empty
    )

    body = (
        struct.pack(">i", 0)  # throttle_time_ms: 0
        + bytes([num_topics + 1])  # topics array length (n + 1)
        + topic
        + bytes([0xFF])  # next_cursor: -1 (null)
        + bytes([0])  # TAG_BUFFER: empty
    )

    message_size = len(header) + len(body)
    return struct.pack(">i", message_size) + header + body


def handle_request(data):
    api_key, api_version, correlation_id, body_offset = parse_request_header(data)

    if api_key == 75:  # DescribeTopicPartitions
        return build_describe_topic_partitions_response(data, correlation_id, body_offset)
    else:  # ApiVersions (18)
        return build_api_versions_response(correlation_id, api_version)


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
