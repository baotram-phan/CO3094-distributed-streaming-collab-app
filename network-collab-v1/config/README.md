# Cấu hình cục bộ

- `users.json`: dữ liệu xác thực PBKDF2 (salt, hash, iterations) mà server sử dụng.
- `users.example.json`: mẫu cấu trúc, không phải danh sách tài khoản hoạt động.
- `app.example.json`: mẫu tham khảo; entry points hiện nhận host/port/chứng chỉ qua tham số dòng lệnh.

`scripts.create_test_users` ghi lại toàn bộ tài khoản mẫu. Không chạy nếu muốn giữ tài khoản hiện có. `scripts.run_all_tests` dùng file tài khoản tạm, không thay thế `users.json`.
