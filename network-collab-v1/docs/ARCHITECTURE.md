# Kiến trúc và trách nhiệm

## Đường đi của dữ liệu

Browser gọi HTTP Bridge localhost. Bridge điều phối `CollaborationClient`; client dùng TCP/TLS để bootstrap và Reliable UDP để gửi AUTH, chat và file đến server. Server relay dữ liệu đến client đích.

| Thành phần | File chính | Trách nhiệm |
|---|---|---|
| Server entry point | `server/main.py` | Tạo registry chung, gắn transport/application, chạy cleanup |
| TLS bootstrap | `server/bootstrap.py` | HELLO/HELLO_ACK, cấp phiên và khóa |
| Quản lý phiên | `server/sessions.py` | ConnID, username, UDP endpoint, trạng thái, deadline |
| AUTH/presence | `server/a16_auth_service.py` | Xác thực, từ chối đăng nhập trùng, danh sách online |
| Chat | `server/a17_chat_service.py`, `server/router.py` | Routing direct/broadcast sau xác thực |
| File relay | `server/transfers.py` | Offer/accept/reject, stream ID, relay và kết quả |
| UDP server | `server/udp_service.py` | Socket dùng chung, đăng ký endpoint, receive/send pump |
| Delivery worker | `server/reliable_dispatcher.py` | Giao bytes đã sắp thứ tự cho application |
| Client | `client/core/session.py`, `client/core/udp_connection.py` | Bootstrap, AUTH, chat/file và heartbeat |
| GUI | `client/bridge/http_server.py`, `client/ui/` | HTTP localhost, hàng đợi lệnh/sự kiện và hiển thị |

## Phiên và endpoint

`BOOTSTRAPPED → UDP_BOUND → ONLINE`. REGISTER hợp lệ gắn IP/cổng UDP vào phiên; AUTH hợp lệ gắn username. Server quản lý endpoint mạng của client, không phải cổng HTTP Bridge 8000/8001. Khi hết hạn hoặc lỗi, registry xóa phiên và đưa sự kiện đóng cho coordinator.

Một username chỉ có một phiên ONLINE. Lần đăng nhập trùng bị từ chối; không thay thế phiên cũ. Lỗi UDP Windows 10054 từ một peer đã đóng không được làm dừng receive loop dùng chung.

## Reliable streams và ranh giới xác nhận

| Stream | Nội dung |
|---|---|
| 0 | AUTH, presence, danh sách online, FILE control, ERROR |
| 1 | Chat riêng/chung và phản hồi chat |
| >= 2 | Bytes file; cấp stream mới cho lượt truyền mới |

ACK xác nhận packet transport; callback application trả True mới cho phép confirm consumption và cập nhật flow credit. Không coi ACK là xác nhận người dùng đã đọc tin. File chỉ được báo COMPLETED khi phía nhận xác nhận kích thước và SHA-256 theo luồng hiện tại.

## Đồng thời và cleanup

- Một SessionRegistry dùng chung giữa TLS bootstrap và UDP.
- UDP pump xử lý gói và lịch gửi; application callback chạy trên delivery worker, ngoài transport/registry locks.
- Delivery xử lý tuần tự theo ConnID. Callback thất bại không tự chạy lại vì có thể tạo side effect trùng.
- Coordinator trong `server/main.py` sở hữu drain close-event và gọi remove_connection trước khi dọn application.
- FileRelay bảo vệ trạng thái bằng khóa; cùng một transfer được ánh xạ đến cả người gửi và người nhận.
- Bridge nhận HTTP trên các request thread; lệnh và sự kiện ứng dụng qua worker riêng.

## Định dạng và giới hạn

UDP header 20 byte, AES-GCM tag 16 byte; DATA chứa tối đa 1024 byte dữ liệu. DATA datagram đầy đủ là 1075 byte, được dùng làm MSS trong congestion accounting runtime. Packet number tăng riêng mỗi chiều; retransmission dùng số mới để tránh tái sử dụng nonce.

Chat tối đa 1000 byte UTF-8. File 1..52.428.800 byte, một transfer đang hoạt động cho mỗi phía. Client gửi file theo khối ứng dụng 128 KiB; transport chia nhỏ thành datagram.

Heartbeat khoảng 2 giây; idle timeout mặc định 10 giây. GUI phân biệt mất HTTP Bridge và mất phiên UDP. Cần đăng nhập lại khi phiên đã đóng; không tự gửi lại chat/file chưa xác nhận.
