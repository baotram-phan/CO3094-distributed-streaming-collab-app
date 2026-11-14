from common.streams import StreamManager
from common.transport import SentPacketTracker, DataRetransmissionQueue
from common.transport_state import TransportConnectionState
from common.window_update_flow import WindowUpdateFlow
from common.send_scheduler import ConnectionSendScheduler


conn_id = 123
key = bytes(range(32))

# 1. Khởi tạo trạng thái cho một kết nối.
streams = StreamManager(conn_id)
connection = TransportConnectionState(conn_id)
sent = SentPacketTracker()
retries = DataRetransmissionQueue(conn_id)
flow = WindowUpdateFlow(streams)

scheduler = ConnectionSendScheduler(streams, connection, sent, retries, flow)

# 2. Đưa dữ liệu chat vào hàng đợi.
streams.queue_bytes(1, b"hello")

print("Da queue 5 bytes vao stream chat.")

# 3. Scheduler kiểm tra credit, tracker và cwnd.
plan = scheduler.prepare_next(
    key,
    now_ms=100,
    cwnd_bytes=10240,
)

assert plan is not None, "Scheduler khong tao duoc DATA"

print("Loai frame:", plan.kind)
print("Stream ID:", plan.stream_id)
print("Kich thuoc datagram:", len(plan.datagram), "bytes")

# 4. Giả lập socket gửi thành công.
scheduler.commit_sent(plan)

print("Packet dang cho ACK:", sent.outstanding_count)
