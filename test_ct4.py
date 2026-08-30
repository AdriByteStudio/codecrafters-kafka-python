import struct, sys, tempfile, os, socket, subprocess, time, threading
sys.path.insert(0, 'app')
import main

def write_varint(value):
    out = b''
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            break
    return out

def write_zigzag(n):
    return write_varint((n << 1) ^ (n >> 63))

def write_compact_string(s):
    b = s.encode('utf-8')
    return write_varint(len(b) + 1) + b

def write_compact_array(count):
    return write_varint(count + 1)

def make_record(value):
    body = bytes([0]) + write_zigzag(0) + write_zigzag(0) + write_zigzag(-1) + write_zigzag(len(value)) + value + write_zigzag(0)
    return write_zigzag(len(body)) + body

def make_batch(records):
    rec_bytes = b''.join(records)
    batch = struct.pack('>q', 0) + struct.pack('>i', 49 + len(rec_bytes)) + struct.pack('>i', 0) + bytes([2]) + struct.pack('>I', 0) + struct.pack('>h', 0) + struct.pack('>i', 0) + struct.pack('>q', 0) + struct.pack('>q', 0) + struct.pack('>q', -1) + struct.pack('>h', -1) + struct.pack('>i', -1) + struct.pack('>i', len(records)) + rec_bytes
    return batch

# Build metadata log
uuid = bytes(range(16))
topic_val = write_varint(1) + write_varint(2) + write_varint(0) + write_compact_string('banana') + uuid + bytes([0])
def part_val(pid):
    v = write_varint(1) + write_varint(3) + write_varint(0)
    v += struct.pack('>i', pid) + uuid
    v += write_compact_array(1) + struct.pack('>i', 1)
    v += write_compact_array(1) + struct.pack('>i', 1)
    v += write_compact_array(0) + write_compact_array(0)
    v += struct.pack('>i', 1) + struct.pack('>i', 0) + struct.pack('>i', 0)
    v += bytes([0])
    return v

log = make_batch([make_record(topic_val), make_record(part_val(0)), make_record(part_val(1)), make_record(part_val(2))])

log_dir = tempfile.mkdtemp()
meta_dir = os.path.join(log_dir, '__cluster_metadata-0')
os.makedirs(meta_dir, exist_ok=True)
with open(os.path.join(meta_dir, '00000000000000000000.log'), 'wb') as f:
    f.write(log)

# server.properties
props = os.path.join(log_dir, 'server.properties')
with open(props, 'w') as f:
    f.write(f'log.dirs={log_dir}\n')

# Start server
server_proc = subprocess.Popen([sys.executable, '-m', 'app.main', props], cwd='.')
time.sleep(1.0)

# Build Produce request
correlation_id = 455338365
header = struct.pack('>hhih', 0, 11, correlation_id, -1) + bytes([0])
body = bytes([0]) + struct.pack('>hi', 2, 0)
body += bytes([2]) + write_compact_string('banana')
body += bytes([4])  # 3 partitions
for i in range(3):
    batch = make_batch([make_record(b'hello world partition %d' % i)])
    # TEST: use varint(len) encoding (NOT len+1)
    body += struct.pack('>i', i) + write_varint(len(batch)) + batch
body += bytes([0]) + bytes([0])
req = struct.pack('>i', len(header)+len(body)) + header + body

try:
    s = socket.create_connection(('localhost', 9092), timeout=5)
    s.sendall(req)
    resp = s.recv(4096)
    print('Response received, len:', len(resp))
    if resp:
        off = 4 + 4 + 1
        n, off = main.read_varint(resp, off)
        name, off = main.read_compact_string(resp, off)
        np, off = main.read_compact_array_count(resp, off)
        print('topics:', n-1, 'name:', name, 'partitions:', np)
        for i in range(np):
            idx = struct.unpack('>i', resp[off:off+4])[0]; off += 4
            ec = struct.unpack('>h', resp[off:off+2])[0]; off += 2
            bo = struct.unpack('>q', resp[off:off+8])[0]; off += 8
            lat = struct.unpack('>q', resp[off:off+8])[0]; off += 8
            lso = struct.unpack('>q', resp[off:off+8])[0]; off += 8
            off += 1 + 1 + 1
            print(f'  partition {idx}: error_code={ec} base_offset={bo}')
    s.close()
except Exception as e:
    print('CLIENT EXCEPTION:', repr(e))

time.sleep(0.5)
server_proc.terminate()
server_proc.wait()
print('DONE')
