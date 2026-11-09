# Giải thích và audit `common/replay.py` — Anti-replay UDP

**Ngày review:** 2026-11-09  
**Source đã xem:** `replay(2).py` do thành viên B tải lên (41 dòng), không tự khẳng định trùng với Git HEAD.  
**Nguồn thiết kế:** `PROTOCOL SPECIFICATION v1.0-proposed` §4.1, §6.1, §9, §12; Integration Contract v1.1-review (luồng REGISTER).  
**Phạm vi:** Giải thích và kiểm thử cô lập; **không sửa source**, chưa có integration test chung A–B.

## 1. Vấn đề cần giải quyết

AES-GCM xác thực nội dung và header của một datagram, nhưng một bản sao nguyên vẹn của datagram cũ vẫn có tag hợp lệ. ReplayWindow ghi nhớ packet numbers đã được **chấp nhận** để từ chối gửi lại cùng packet. UDP có thể giao packet *sai thứ tự*, nên không thể chỉ giữ một biến `highest` rồi yêu cầu mọi packet phải lớn hơn `highest`.

Ví dụ: đã nhận packet 0, 2, chưa nhận 1; khi packet 1 đến sau, nếu nó hợp lệ và còn nằm trong cửa sổ thì vẫn phải nhận.

Đây là anti-replay ở tầng UDP **theo từng ConnID và từng chiều nhận**, không thay thế xác thực AES-GCM, kiểm tra endpoint, kiểm tra trạng thái session hoặc cơ chế chống giao dữ liệu trùng trên stream offset.

## 2. Ba thành phần

| Hàm/biến | Ý nghĩa | Không làm gì |
|---|---|---|
| `ReplayWindow(size=4096)` | Khởi tạo cửa sổ; `size` là **số packet numbers**, không phải số byte | Không tạo ConnID/key hoặc socket |
| `highest = -1` | Số lớn nhất đã commit; `-1` là sentinel chưa nhận gói nào | Không phải packet number hợp lệ trên dây |
| `received = set()` | Tập các packet numbers đã commit và còn trong cửa sổ | Không lưu payload, không lưu key |
| `can_accept(pkt_num) -> bool` | Kiểm tra kiểu, miền uint64, độ cũ và trùng; **chỉ đọc**, không ghi state | Không xác thực AES-GCM |
| `commit(pkt_num) -> bool` | Nếu còn hợp lệ, cập nhật `highest`, thêm số vào `received`, loại số ngoài cửa sổ | Không đảm bảo thread-safe nếu nhiều handler cùng ConnID |

### `__init__(size: int = 4096)`

- `type(size) is not int`: không nhận `True` dù `bool` trong Python tương đương số nguyên trong phép so sánh.
- `size <= 0`: cửa sổ phải có độ rộng dương.
- `highest = -1`: packet đầu tiên có thể là `0`; tránh coi `0` là đã nhận.
- `received = set()`: kiểm tra tồn tại `pkt_num in self.received` trung bình nhanh, mỗi số chỉ lưu một lần. `set` là lựa chọn implementation, không phải on-wire format.

### `can_accept(pkt_num)` — quyết định tạm thời, **không đánh dấu**

```python
if type(pkt_num) is not int:
    return False
if not (0 <= pkt_num < (1 << 64)):
    return False
if pkt_num <= self.highest - self.size:
    return False
if pkt_num in self.received:
    return False
return True
```

1. Loại kiểu sai (`bool`, `float`, `str`, ...).
2. Loại giá trị ngoài miền `uint64`.
3. Loại packet quá cũ: nếu `highest = 6`, `size = 4`, thì số `<= 2` ngoài cửa sổ, còn `3` là ranh giới được phép.
4. Loại số đã có trong tập `received` (packet trùng).
5. Với số mới nằm trong cửa sổ hoặc số lớn hơn `highest`, cho phép **đi tiếp đến các bước xác thực**, chưa coi là packet hợp lệ cuối cùng.

**Vì sao cần tách `can_accept()` và `commit()`?** Nếu đánh dấu số packet trước khi xác minh AES-GCM, một packet giả mạo với `pkt_num` rất lớn có thể đẩy `highest` lên, khiến các packet thật bị từ chối là quá cũ. Vì vậy `can_accept` chỉ là bước sàng lọc ban đầu.

### `commit(pkt_num)` — ghi nhận sau khi đã xác thực

```python
if not self.can_accept(pkt_num):
    return False
self.highest = max(self.highest, pkt_num)
self.received.add(pkt_num)
cutoff = self.highest - self.size + 1
self.received = {num for num in self.received if num >= cutoff}
return True
```

- Gọi lại `can_accept`: ngăn commit giá trị trùng/quá cũ/tạo lỗi kiểu.
- `max`: packet đến sai thứ tự không làm `highest` giảm.
- `add`: đánh dấu số vừa chấp nhận.
- `cutoff = highest - size + 1`: ngưỡng **bao gồm** số nhỏ nhất vẫn còn trong cửa sổ.
- Lọc `received`: chỉ giữ số lớn hơn hoặc bằng `cutoff`, tránh lưu vô hạn lịch sử.
- Trả `True` khi việc commit thành công.

## 3. Minh họa bằng cửa sổ nhỏ size=4

Ví dụ dùng `size=4` **chỉ để dễ học và unit test**; protocol đề xuất 4096 trong môi trường thật.

| Lệnh | `highest` sau đó | `received` sau đó | Kết luận |
|---|---:|---|---|
| Khởi tạo | -1 | `{}` | Chưa nhận gì |
| `commit(0)` | 0 | `{0}` | Nhận packet đầu tiên |
| `commit(2)` | 2 | `{0,2}` | Chấp nhận dù 1 chưa đến |
| `commit(1)` | 2 | `{0,1,2}` | Chấp nhận packet đến muộn |
| `commit(2)` | 2 | `{0,1,2}` | `False` vì số 2 đã nhận |
| `commit(6)` | 6 | `{6}` | `cutoff = 6-4+1 = 3`; xóa 0,1,2 khỏi tập |
| `can_accept(2)` | 6 | `{6}` | `False`: quá cũ dù không còn trong set |
| `can_accept(3)` | 6 | `{6}` | `True`: ranh giới cửa sổ và chưa nhận |

Lưu ý `can_accept(3)` không cập nhật tập; chỉ `commit(3)` mới đánh dấu 3 đã được nhận.

Với `size=4096`, nếu `highest=5000`, số nhỏ nhất còn trong cửa sổ là `905`, vì `5000 - 4096 + 1 = 905`.

## 4. Ranh giới với các module khác

```text
UDP socket nhận datagram
  → udp_packet.decode_header: kiểm tra cấu trúc, đọc ConnID/pkt_num (CHƯA XÁC THỰC)
  → SessionRegistry.get(conn_id): tra cứu session/key theo A
  → ReplayWindow.can_accept(pkt_num): lọc trùng/quá cũ, chưa commit
  → crypto AES-GCM / udp_packet.decode_packet: xác thực tag và header AAD
  → Registry.bind_udp_verified_with_status (REGISTER) hoặc touch_verified_udp (sau REGISTER)
  → ReplayWindow.commit(pkt_num): chỉ sau khi mọi điều kiện hợp lệ
  → handler xử lý packet / gửi REGISTER_OK với server packet number mới
```

**Quan trọng:** Đây là trình tự logic theo contract, không phải khẳng định source UDP Service đã viết. Cần xử lý tuần tự theo từng ConnID, đồng thời tuân thủ quy tắc **không giữ transport lock khi gọi Registry**. Bản MVP có thể dùng một receive loop xử lý tuần tự; khi song song hóa cần thiết kế lại cơ chế phối hợp sao cho không tạo race giữa `can_accept`, decrypt, Registry và `commit`.

- `replay.py` không phân biệt REGISTER/DATA/PING; nó chỉ kiểm tra packet number.
- Mỗi ConnID có ReplayWindow nhận độc lập, không dùng chung cho client khác hoặc hai chiều.
- `pkt_num` phục vụ chống replay/nonce/ACK; `stream offset` phục vụ thứ tự nội dung và loại dữ liệu giao trùng. Không dùng replay window thay thế stream reorder/duplicate prevention.
- Khi phiên hết hạn, transport state và replay state cần được cleanup theo `SessionClosedEvent` của Registry, không tạo lại state với khóa phiên cũ.

## 5. Đối chiếu protocol và đánh giá code

| Nguồn yêu cầu | Trạng thái code `replay(2).py` |
|---|---|
| §4.1: cửa sổ mặc định 4096 packet numbers | Có, `size=4096` |
| §4.1: chống gửi lại cùng packet | Có, `pkt_num in received` |
| §4.1: chấp nhận packet sai thứ tự trong cửa sổ | Có, không buộc `pkt_num > highest` |
| §4.1: chỉ ghi nhận packet sau xác thực AES-GCM | **Phải bảo đảm tại caller**; không phải chức năng riêng của class |
| §4.1: không dùng bộ nhớ vô hạn để ghi toàn lịch sử | Có, lọc tập theo cutoff; hiệu năng cần đo |
| Contract v1.1: thứ tự REGISTER/replay/bind và serialization cùng ConnID | **Chưa được kiểm chứng tích hợp** |

**Không có bằng chứng rằng logic tuần tự trong file vi phạm protocol.** Nhưng class không tự đảm bảo bảo mật đầu-cuối khi caller dùng sai thứ tự.

## 6. Code smell và giới hạn kỹ thuật

1. `self.received = { ... }` duyệt lại toàn bộ set sau **mỗi** lần commit, chi phí O(số phần tử trong cửa sổ), tối đa khoảng 4096 phần tử theo cấu hình mặc định. Đây là điểm nên benchmark trước khi chuyển file lớn; chưa cần tối ưu vội nếu chưa đo.
2. Class không có lock; cả `can_accept` lẫn `commit` không bảo đảm nguyên tử khi nhiều thread xử lý cùng ConnID. Chỉ thêm lock cho từng hàm riêng lẻ không đủ bảo vệ chuỗi xác thực/Registry/commit.
3. Không giới hạn giá trị `size` phía trên; caller nội bộ cần quản lý cấu hình thay vì cho input chưa tin cậy tùy ý tạo cửa sổ rất lớn.
4. Số packet nhảy vọt sẽ làm cửa sổ dịch theo. Việc này đúng về thuật toán; **chỉ được commit sau xác thực** để packet giả mạo không làm dịch cửa sổ.
5. `ReplayWindow` chỉ ghi trạng thái nhận, không tự sinh packet numbers gửi. Phần cấp số gửi thuộc `TransportConnectionState`.

## 7. Bằng chứng kiểm thử cô lập (2026-11-09)

Đã nạp chính `replay(2).py` và chạy **8 tests độc lập** trên bản được tải lên: khởi tạo, sai thứ tự, trùng, ranh giới 4-slot, `can_accept` không commit, sai kiểu/range, size không hợp lệ, khoảng nhảy lớn. **8/8 PASS**. Kết quả này không chứng minh Git HEAD hay toàn bộ 33 unit tests vẫn PASS.

### Các unit test nên lưu trong repo

```python
import unittest
from common.replay import ReplayWindow

class TestReplayWindow(unittest.TestCase):
    def test_out_of_order_and_duplicate(self):
        w = ReplayWindow(size=4)
        self.assertTrue(w.commit(0))
        self.assertTrue(w.commit(2))
        self.assertTrue(w.commit(1))
        self.assertFalse(w.commit(2))
        self.assertEqual(w.highest, 2)

    def test_boundary(self):
        w = ReplayWindow(size=4)
        for n in (0, 1, 2, 6):
            self.assertTrue(w.commit(n))
        self.assertFalse(w.can_accept(2))
        self.assertTrue(w.can_accept(3))

    def test_can_accept_does_not_commit(self):
        w = ReplayWindow()
        self.assertTrue(w.can_accept(7))
        self.assertTrue(w.can_accept(7))
        self.assertEqual(w.highest, -1)
        self.assertEqual(w.received, set())

    def test_invalid_numbers(self):
        w = ReplayWindow()
        for x in (-1, True, 1.0, "5", 1 << 64):
            self.assertFalse(w.can_accept(x))
```

Chạy sau khi đưa test vào repo: `python -m unittest discover -s tests -v`. Không ghi PASS nếu chưa chạy trên commit của bạn.

## 8. Điều cần giải thích khi bảo vệ

> `ReplayWindow` là bộ lọc anti-replay cho UDP packet numbers, theo từng kết nối và từng chiều nhận. Nó có `highest` để giới hạn phạm vi số còn xem xét và `received` để nhận diện số đã dùng. Do UDP có thể đảo thứ tự, số nhỏ hơn `highest` vẫn được chấp nhận nếu chưa xuất hiện và còn trong cửa sổ. Chúng em chỉ commit packet number sau AES-GCM verification và session/endpoint validation, để packet giả không đẩy cửa sổ và làm mất packet hợp lệ.

## 9. Ghi nhận tài liệu Git

Tài liệu này được xây dựng từ source đã tải lên. **Không thay đổi protocol hoặc source; chưa chạy kiểm thử tích hợp A–B.** Khi commit, ghi commit hash và kết quả test thật, tránh ghi lại số lượng test cũ như một kết quả mới.
