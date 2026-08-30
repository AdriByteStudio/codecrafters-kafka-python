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


def write_varint(value):
    """Encode an unsigned varint. Returns bytes."""
    out = b""
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            break
    return out


def write_compact_string(s):
    """Encode a COMPACT_STRING (varint(len + 1) + bytes)."""
    b = s.encode("utf-8")
    return write_varint(len(b) + 1) + b


def write_compact_array(count):
    """Encode a COMPACT_ARRAY length prefix (varint(count + 1))."""
    return write_varint(count + 1)


def read_topic_log_records(topic_name):
    """Read the record batch(es) from a topic's log file on disk.

    Returns the raw record batch bytes, or None if the file doesn't exist.
    """
    log_path = f"/tmp/kraft-combined-logs/{topic_name}-0/00000000000000000000.log"
    try:
        with open(log_path, "rb") as f:
            return f.read()
    except OSError:
        return None


def read_zigzag_varint(data, offset):
    """Read a zigzag-encoded varint. Returns (value, new_offset)."""
    v, offset = read_varint(data, offset)
    return ((v >> 1) ^ -(v & 1)), offset


def read_compact_string(data, offset):
    """Read a COMPACT_STRING. Returns (string_or_None, new_offset)."""
    n, offset = read_varint(data, offset)
    if n == 0:
        return None, offset  # null
    length = n - 1
    s = data[offset:offset + length].decode("utf-8")
    return s, offset + length


def read_compact_array_count(data, offset):
    """Read a COMPACT_ARRAY length prefix. Returns (count_or_None, new_offset)."""
    n, offset = read_varint(data, offset)
    if n == 0:
        return None, offset  # null
    return n - 1, offset


def read_uuid(data, offset):
    """Read a UUID (16 bytes). Returns (bytes, new_offset)."""
    return data[offset:offset + 16], offset + 16


def skip_tag_buffer(data, offset):
    """Skip a TAGGED_FIELDS structure. Returns new_offset."""
    num_fields, offset = read_varint(data, offset)
    for _ in range(num_fields):
        _, offset = read_varint(data, offset)  # tag
        size, offset = read_varint(data, offset)  # size
        offset += size
    return offset


def parse_topic_record(data, offset):
    """Parse a TopicRecord value. Returns (dict, new_offset)."""
    name, offset = read_compact_string(data, offset)
    topic_id, offset = read_uuid(data, offset)
    offset = skip_tag_buffer(data, offset)
    return {"name": name, "topic_id": topic_id}, offset


def parse_partition_record(data, offset, version):
    """Parse a PartitionRecord value. Returns (dict, new_offset)."""
    partition_id = struct.unpack(">i", data[offset:offset + 4])[0]
    offset += 4
    topic_id, offset = read_uuid(data, offset)

    def read_int32_array(offset):
        count, offset = read_compact_array_count(data, offset)
        arr = []
        for _ in range(count):
            arr.append(struct.unpack(">i", data[offset:offset + 4])[0])
            offset += 4
        return arr, offset

    replicas, offset = read_int32_array(offset)
    isr, offset = read_int32_array(offset)
    removing, offset = read_int32_array(offset)
    adding, offset = read_int32_array(offset)
    leader = struct.unpack(">i", data[offset:offset + 4])[0]
    offset += 4
    leader_epoch = struct.unpack(">i", data[offset:offset + 4])[0]
    offset += 4
    partition_epoch = struct.unpack(">i", data[offset:offset + 4])[0]
    offset += 4

    directories = []
    if version >= 1:
        count, offset = read_compact_array_count(data, offset)
        for _ in range(count):
            d, offset = read_uuid(data, offset)
            directories.append(d)

    # TAG_BUFFER: read tagged fields (tag 0 = LeaderRecoveryState)
    num_tags, offset = read_varint(data, offset)
    leader_recovery_state = 0
    for _ in range(num_tags):
        tag, offset = read_varint(data, offset)
        size, offset = read_varint(data, offset)
        if tag == 0:
            leader_recovery_state = data[offset]
        offset += size

    return {
        "partition_id": partition_id,
        "topic_id": topic_id,
        "replicas": replicas,
        "isr": isr,
        "leader": leader,
        "leader_epoch": leader_epoch,
        "partition_epoch": partition_epoch,
        "directories": directories,
        "leader_recovery_state": leader_recovery_state,
    }, offset


def parse_metadata_value(value):
    """Parse the value bytes of a metadata record. Returns (dict, new_offset)."""
    offset = 0
    frame_version, offset = read_varint(value, offset)  # expect 1
    rec_type, offset = read_varint(value, offset)  # 2 = TOPIC_RECORD, 3 = PARTITION_RECORD
    version, offset = read_varint(value, offset)
    if rec_type == 2:
        return parse_topic_record(value, offset)
    elif rec_type == 3:
        return parse_partition_record(value, offset, version)
    else:
        return None, offset


def load_cluster_metadata(log_path):
    """Parse the cluster metadata log file.

    Returns (topics_by_name, partitions_by_topic_id).
    topics_by_name: { name: topic_id_bytes }
    partitions_by_topic_id: { topic_id_bytes: [partition_dict, ...] }
    """
    topics = {}
    partitions = {}
    try:
        with open(log_path, "rb") as f:
            data = f.read()
    except OSError:
        return topics, partitions

    offset = 0
    while offset < len(data):
        base_offset = struct.unpack(">q", data[offset:offset + 8])[0]
        offset += 8
        batch_length = struct.unpack(">i", data[offset:offset + 4])[0]
        offset += 4
        batch_end = offset + batch_length
        offset += 4  # partitionLeaderEpoch
        magic = data[offset]
        offset += 1
        offset += 4  # crc
        offset += 2  # attributes
        offset += 4  # lastOffsetDelta
        offset += 8  # baseTimestamp
        offset += 8  # maxTimestamp
        offset += 8  # producerId
        offset += 2  # producerEpoch
        offset += 4  # baseSequence
        records_count = struct.unpack(">i", data[offset:offset + 4])[0]
        offset += 4

        for _ in range(records_count):
            # Record length is ZigZag-encoded (writeVarint uses encodeZigzag32)
            rec_len, offset = read_zigzag_varint(data, offset)
            rec_end = offset + rec_len
            offset += 1  # attributes
            _, offset = read_zigzag_varint(data, offset)  # timestampDelta
            _, offset = read_zigzag_varint(data, offset)  # offsetDelta
            key_len, offset = read_zigzag_varint(data, offset)
            if key_len >= 0:
                offset += key_len
            val_len, offset = read_zigzag_varint(data, offset)
            if val_len >= 0:
                value = data[offset:offset + val_len]
                offset += val_len
                parsed, _ = parse_metadata_value(value)
                if parsed is not None and "name" in parsed:
                    topics[parsed["name"]] = parsed["topic_id"]
                elif parsed is not None and "partition_id" in parsed:
                    partitions.setdefault(parsed["topic_id"], []).append(parsed)
            # Headers: also ZigZag-encoded in DefaultRecord
            hcount, offset = read_zigzag_varint(data, offset)
            for _ in range(hcount):
                hk_len, offset = read_zigzag_varint(data, offset)
                offset += hk_len
                hv_len, offset = read_zigzag_varint(data, offset)
                offset += hv_len
            offset = rec_end
        offset = batch_end
    return topics, partitions


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
    #   - API key 0 (Produce), versions 0-11
    #   - API key 1 (Fetch), versions 0-16
    #   - API key 18 (ApiVersions), versions 0-4
    #   - API key 75 (DescribeTopicPartitions), versions 0-0
    # COMPACT_ARRAY length is encoded as n + 1 (unsigned varint). With 4 elements, that's 5.
    api_keys = (
        bytes([5])  # array length: 4 elements -> 5
        + struct.pack(">h", 0)  # api_key: 0 (Produce)
        + struct.pack(">h", 0)  # min_version: 0
        + struct.pack(">h", 11)  # max_version: 11
        + bytes([0])  # TAG_BUFFER: empty
        + struct.pack(">h", 1)  # api_key: 1 (Fetch)
        + struct.pack(">h", 0)  # min_version: 0
        + struct.pack(">h", 16)  # max_version: 16
        + bytes([0])  # TAG_BUFFER: empty
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


def build_partition_entry(partition):
    """Build a single partition entry for the DescribeTopicPartitions response."""
    replicas = partition["replicas"]
    isr = partition["isr"]

    def compact_array(elements):
        # COMPACT_ARRAY: varint(len + 1), then elements
        return bytes([len(elements) + 1]) + b"".join(struct.pack(">i", e) for e in elements)

    return (
        struct.pack(">h", 0)  # error_code: 0 (no error)
        + struct.pack(">i", partition["partition_id"])  # partition_index
        + struct.pack(">i", partition["leader"])  # leader_id
        + struct.pack(">i", partition["leader_epoch"])  # leader_epoch
        + compact_array(replicas)  # replica_nodes
        + compact_array(isr)  # isr_nodes
        + bytes([1])  # eligible_leader_replicas: 0 elements (empty)
        + bytes([1])  # last_known_elr: 0 elements (empty)
        + bytes([1])  # offline_replicas: 0 elements (empty)
        + bytes([0])  # TAG_BUFFER: empty
    )


def build_topic_entry(topic_name, topics, partitions):
    """Build a single topic entry for the DescribeTopicPartitions response."""
    # Look up the topic in the cluster metadata.
    topic_id = topics.get(topic_name.decode("utf-8"))
    if topic_id is not None:
        error_code = 0
        topic_partitions = partitions.get(topic_id, [])
        topic_partitions.sort(key=lambda p: p["partition_id"])
        partition_entries = b"".join(build_partition_entry(p) for p in topic_partitions)
        partitions_array = bytes([len(topic_partitions) + 1]) + partition_entries
    else:
        error_code = 3  # UNKNOWN_TOPIC_OR_PARTITION
        topic_id = bytes(16)  # all zeros
        partitions_array = bytes([1])  # 0 elements (empty)

    return (
        struct.pack(">h", error_code)  # error_code
        + bytes([len(topic_name) + 1])  # topic_name length (compact string: n + 1)
        + topic_name  # topic_name
        + topic_id  # topic_id
        + bytes([0])  # is_internal: false
        + partitions_array  # partitions
        + struct.pack(">i", 0)  # topic_authorized_operations: 0
        + bytes([0])  # TAG_BUFFER: empty
    )


def build_describe_topic_partitions_response(data, correlation_id, body_offset, topics, partitions):
    # Parse the request body to extract all topic names.
    # DescribeTopicPartitions request (v0) body:
    #   topics: COMPACT_ARRAY of { topic_name: COMPACT_STRING, TAG_BUFFER }
    #   TAG_BUFFER
    offset = body_offset
    num_topics, offset = read_varint(data, offset)  # topics array length (n + 1)
    num_topics -= 1

    topic_names = []
    for _ in range(num_topics):
        name_len, offset = read_varint(data, offset)  # COMPACT_STRING length (n + 1)
        name_len -= 1
        topic_name = data[offset:offset + name_len]
        offset += name_len
        offset = skip_tag_buffer(data, offset)  # topic's TAG_BUFFER
        topic_names.append(topic_name)

    # Response header v1: correlation_id (INT32) + TAG_BUFFER (empty)
    header = struct.pack(">i", correlation_id) + bytes([0])

    # Build a topic entry for each requested topic, sorted alphabetically by name.
    topic_names.sort()
    topic_entries = b"".join(build_topic_entry(name, topics, partitions) for name in topic_names)

    body = (
        struct.pack(">i", 0)  # throttle_time_ms: 0
        + bytes([len(topic_names) + 1])  # topics array length (n + 1)
        + topic_entries
        + bytes([0xFF])  # next_cursor: -1 (null)
        + bytes([0])  # TAG_BUFFER: empty
    )

    message_size = len(header) + len(body)
    return struct.pack(">i", message_size) + header + body


def build_fetch_response(data, correlation_id, body_offset, topics, partitions):
    """Build a Fetch (v16) response.

    Fetch Response (Version: 16):
      throttle_time_ms => INT32
      error_code => INT16
      session_id => INT32
      responses => COMPACT_ARRAY of { topic_id, partitions }
      [node_endpoints]<tag: 0> (omitted)

    Each requested topic gets a response entry. For an unknown topic, the
    partition entry carries error_code 100 (UNKNOWN_TOPIC_ID). For a known
    topic with no messages, the partition entry carries error_code 0 and an
    empty records batch.
    """
    # Parse the Fetch request body to extract the requested topic IDs.
    # Fetch Request (Version: 16) body:
    #   max_wait_ms(INT32) min_bytes(INT32) max_bytes(INT32) isolation_level(INT8)
    #   session_id(INT32) session_epoch(INT32)
    #   [topics] (COMPACT_ARRAY of { topic_id(UUID), [partitions], TAG_BUFFER })
    offset = body_offset
    offset += 4  # max_wait_ms
    offset += 4  # min_bytes
    offset += 4  # max_bytes
    offset += 1  # isolation_level
    offset += 4  # session_id
    offset += 4  # session_epoch
    num_topics, offset = read_compact_array_count(data, offset)
    topic_ids = []
    for _ in range(num_topics):
        topic_id, offset = read_uuid(data, offset)
        topic_ids.append(topic_id)
        num_partitions, offset = read_compact_array_count(data, offset)
        for _ in range(num_partitions):
            offset += 4  # partition
            offset += 4  # current_leader_epoch
            offset += 8  # fetch_offset
            offset += 4  # last_fetched_epoch
            offset += 8  # log_start_offset
            offset += 4  # partition_max_bytes
            offset = skip_tag_buffer(data, offset)  # partition TAG_BUFFER
        offset = skip_tag_buffer(data, offset)  # topic TAG_BUFFER

    # Response header v1: correlation_id (INT32) + TAG_BUFFER (empty)
    header = struct.pack(">i", correlation_id) + bytes([0])

    # Build a reverse mapping from topic_id -> topic_name so we can locate the
    # topic's log file on disk.
    topic_id_to_name = {v: k for k, v in topics.items()}

    # Build each topic entry. For an unknown topic, return error_code 100.
    # For a known topic, read the record batch(es) from its log file on disk
    # and return them in the records field.
    topic_entries = b""
    for topic_id in topic_ids:
        if topic_id in partitions:
            error_code = 0  # No Error
            topic_name = topic_id_to_name.get(topic_id)
            batch = read_topic_log_records(topic_name) if topic_name else None
            if batch:
                # COMPACT_RECORDS: varint(len + 1) + record batch bytes
                records = write_varint(len(batch) + 1) + batch
            else:
                records = bytes([1])  # empty records batch (0 bytes of data)
        else:
            error_code = 100  # UNKNOWN_TOPIC_ID
            records = bytes([0])  # null records
        partition = (
            struct.pack(">i", 0)  # partition_index: 0
            + struct.pack(">h", error_code)  # error_code
            + struct.pack(">q", -1)  # high_watermark: -1
            + struct.pack(">q", -1)  # last_stable_offset: -1
            + struct.pack(">q", -1)  # log_start_offset: -1
            + bytes([1])  # aborted_transactions: empty array (n + 1 = 1)
            + struct.pack(">i", -1)  # preferred_read_replica: -1
            + records  # records (COMPACT_RECORDS)
            + bytes([0])  # TAG_BUFFER: empty
        )
        topic_entries += (
            topic_id  # topic_id: UUID
            + bytes([2])  # partitions array: 1 element (n + 1 = 2)
            + partition
            + bytes([0])  # topic TAG_BUFFER: empty
        )

    body = (
        struct.pack(">i", 0)  # throttle_time_ms: 0
        + struct.pack(">h", 0)  # error_code: 0
        + struct.pack(">i", 0)  # session_id: 0
        + bytes([len(topic_ids) + 1])  # responses array: N elements (n + 1)
        + topic_entries
        + bytes([0])  # TAG_BUFFER: empty (no node_endpoints)
    )

    message_size = len(header) + len(body)
    return struct.pack(">i", message_size) + header + body


def build_produce_response(data, correlation_id, body_offset):
    """Build a Produce (v11) response for invalid topics or partitions.

    Produce Response (Version: 11):
      throttle_time_ms => INT32
      responses => COMPACT_ARRAY of { name, partition_responses }
      TAG_BUFFER

    Each partition response carries error_code 3 (UNKNOWN_TOPIC_OR_PARTITION)
    with base_offset, log_append_time_ms, and log_start_offset all -1.
    """
    # Parse the Produce request body to extract topic names and partition indexes.
    # Produce Request (Version: 11) body:
    #   transactional_id(COMPACT_NULLABLE_STRING) acks(INT16) timeout_ms(INT32)
    #   [topic_data] (COMPACT_ARRAY of { name(COMPACT_STRING),
    #     [partition_data] (COMPACT_ARRAY of { index(INT32), records(COMPACT_RECORDS) }),
    #     TAG_BUFFER })
    offset = body_offset
    # transactional_id: COMPACT_NULLABLE_STRING (varint; 0 = null)
    tid_len, offset = read_varint(data, offset)
    if tid_len > 0:
        offset += tid_len - 1
    offset += 2  # acks
    offset += 4  # timeout_ms
    num_topics, offset = read_compact_array_count(data, offset)
    topic_entries = b""
    for _ in range(num_topics):
        name, offset = read_compact_string(data, offset)
        num_partitions, offset = read_compact_array_count(data, offset)
        partition_entries = b""
        for _ in range(num_partitions):
            index, offset = struct.unpack(">i", data[offset:offset + 4])[0], offset + 4
            # records: COMPACT_RECORDS (varint length + data)
            rec_len, offset = read_varint(data, offset)
            if rec_len > 0:
                offset += rec_len - 1
            # Build the partition response entry with error_code 3.
            partition_entries += (
                struct.pack(">i", index)  # index
                + struct.pack(">h", 3)  # error_code: 3 (UNKNOWN_TOPIC_OR_PARTITION)
                + struct.pack(">q", -1)  # base_offset: -1
                + struct.pack(">q", -1)  # log_append_time_ms: -1
                + struct.pack(">q", -1)  # log_start_offset: -1
                + bytes([1])  # record_errors: empty array (n + 1 = 1)
                + bytes([0])  # error_message: null
                + bytes([0])  # TAG_BUFFER: empty
            )
        topic_entries += (
            write_compact_string(name)  # name
            + write_compact_array(num_partitions)  # partition_responses array
            + partition_entries
            + bytes([0])  # TAG_BUFFER: empty
        )
        offset = skip_tag_buffer(data, offset)  # topic TAG_BUFFER

    # Response header v1: correlation_id (INT32) + TAG_BUFFER (empty)
    header = struct.pack(">i", correlation_id) + bytes([0])

    body = (
        struct.pack(">i", 0)  # throttle_time_ms: 0
        + write_compact_array(num_topics)  # responses array
        + topic_entries
        + bytes([0])  # TAG_BUFFER: empty
    )

    message_size = len(header) + len(body)
    return struct.pack(">i", message_size) + header + body


def handle_request(data, topics, partitions):
    api_key, api_version, correlation_id, body_offset = parse_request_header(data)

    if api_key == 75:  # DescribeTopicPartitions
        return build_describe_topic_partitions_response(data, correlation_id, body_offset, topics, partitions)
    elif api_key == 1:  # Fetch
        return build_fetch_response(data, correlation_id, body_offset, topics, partitions)
    elif api_key == 0:  # Produce
        return build_produce_response(data, correlation_id, body_offset)
    else:  # ApiVersions (18)
        return build_api_versions_response(correlation_id, api_version)


def handle_connection(conn, topics, partitions):
    with conn:
        # Handle multiple sequential requests on the same connection.
        while True:
            data = conn.recv(1024)
            if not data:
                break  # client closed the connection
            response = handle_request(data, topics, partitions)
            conn.sendall(response)


def main():
    # Load cluster metadata from the log file.
    log_path = "/tmp/kraft-combined-logs/__cluster_metadata-0/00000000000000000000.log"
    topics, partitions = load_cluster_metadata(log_path)

    server = socket.create_server(("localhost", 9092), reuse_port=True)
    while True:
        conn, addr = server.accept()
        # Handle each client connection in its own thread to support concurrency.
        thread = threading.Thread(target=handle_connection, args=(conn, topics, partitions))
        thread.start()


if __name__ == "__main__":
    main()
