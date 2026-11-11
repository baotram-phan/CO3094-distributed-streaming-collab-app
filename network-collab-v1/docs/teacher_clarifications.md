# Trích yếu Giải đáp Assignment 1 (6 trang)

**Không thay thế PDF gốc do giảng viên cung cấp.** Hãy lưu PDF riêng và đọc cùng khi review.

- Trang 1: tin nhắn và dữ liệu file đi qua giao thức UDP tự thiết kế; TCP bootstrap được phép.
- Trang 2–3: tự làm streams, ACK ranges, retransmission, RTT/RTO, sliding window; không dùng QUIC/KCP có sẵn.
- Trang 3–4: chọn CUBIC hoặc BBR và kiểm chứng bằng log/biểu đồ cwnd.
- Trang 4: X25519 + HKDF + AES-GCM là **một phương án được chấp nhận**, không phải thuật toán bắt buộc.
- Trang 5: server relay hoặc P2P đều được chấp nhận; file nằm trong stream riêng.
- Trang 5–6: localhost được chấp nhận; cần mô phỏng mất gói/độ trễ/reorder và chứng minh SHA-256, HoL.

**Quyết định riêng của nhóm**: TLS bootstrap + AES-256-GCM UDP; file relay, CUBIC,
Python `http.server`. Chưa coi là đã được thầy duyệt toàn bộ.
