# Test suite

Chạy từ thư mục gốc: `python -m scripts.run_all_tests`.

Runner dùng tài khoản tạm. Các unit/integration tests kiểm tra framing, authentication, sessions, packet crypto, streams, ACK/RTO, congestion, chat, file, HTTP Bridge và lỗi kết nối.

Xem [docs/TESTING.md](../docs/TESTING.md) cho lệnh kiểm thử, các test skip trên Windows và checklist demo. Giữ nguyên tên test/module để tương thích import. Một số file sườn không chứa test case không được tính là bằng chứng kiểm thử.
