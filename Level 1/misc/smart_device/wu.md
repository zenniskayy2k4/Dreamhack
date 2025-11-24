### Write-up: [Misc] smart_device - ACSC CTF

**Tên thử thách:** smart_device
**Thể loại:** Misc / Forensics
**Mô tả:** Get API Key from smart device :D

#### Tóm tắt

Thử thách cung cấp một file `smart_firmware.img`, là một file firmware của một thiết bị thông minh. Mục tiêu là phân tích file này để tìm ra API Key. Hướng giải quyết là xác định đúng định dạng của file, giải nén nó, và tìm kiếm trong hệ thống file được trích xuất để tìm file cấu hình chứa key.

---

### Các bước thực hiện chi tiết

#### Bước 1: Phân tích file ban đầu

Khi nhận được file `smart_firmware.img`, bước đầu tiên là xác định bản chất của nó. Sử dụng công cụ `file` là cách nhanh nhất.

```bash
$ file smart_firmware.img
smart_firmware.img: gzip compressed data, from Unix, original size modulo 2^32 20480
```

Kết quả cho thấy đây không phải là một file ảnh đĩa (`disk image`) có thể `mount` trực tiếp, mà là một file dữ liệu đã được nén bằng thuật toán `gzip`.

#### Bước 2: Giải nén Firmware

Vì đây là file nén `gzip`, chúng ta cần giải nén nó để xem nội dung bên trong. Để an toàn, ta sẽ giải nén ra một file mới tên là `decompressed_firmware` và giữ lại file gốc.

```bash
$ gzip -dc smart_firmware.img > decompressed_firmware
```

Sau khi giải nén, chúng ta tiếp tục kiểm tra định dạng của file mới.

```bash
$ file decompressed_firmware
decompressed_firmware: POSIX tar archive (GNU)
```

Kết quả cho thấy file vừa giải nén là một file lưu trữ dạng `tar`. Điều này có nghĩa là firmware này thực chất là một tập hợp các file và thư mục của hệ thống được đóng gói lại.

#### Bước 3: Trích xuất hệ thống file

Tiếp theo, chúng ta sẽ giải nén file `tar` này vào một thư mục riêng để tiện cho việc phân tích.

```bash
# Tạo một thư mục để chứa các file được giải nén
$ mkdir extracted_firmware

# Giải nén file tar vào thư mục vừa tạo
$ tar -xvf decompressed_firmware -C extracted_firmware
./
./bin/
./bin/check_status
./etc/
./etc/device.conf
./etc/init.d/
./etc/init.d/rcS
./etc/passwd
./root/
./sbin/
./tmp/
./usr/
./usr/bin/
./var/
./var/log/
./var/log/messages
```

Sau khi giải nén, chúng ta có được cấu trúc thư mục của một hệ điều hành Linux thu nhỏ, bao gồm các thư mục quen thuộc như `/etc`, `/bin`, `/root`, v.v.

#### Bước 4: Tìm kiếm API Key

Giờ đây chúng ta đã có quyền truy cập vào toàn bộ hệ thống file của thiết bị. Mục tiêu là tìm kiếm API Key. Dựa trên kinh nghiệm, các thông tin nhạy cảm như key, mật khẩu thường được lưu trong các file cấu hình, đặc biệt là trong thư mục `/etc`.

Quan sát danh sách các file đã trích xuất, file `etc/device.conf` có vẻ là "nghi phạm" hàng đầu. Tên của nó gợi ý rằng đây là file cấu hình chính của thiết bị.

Chúng ta hãy đọc nội dung của file này:

```bash
$ cd extracted_firmware
$ cat etc/device.conf
```

Kết quả trả về:
```ini
# ACSC Smart Device Configuration File
# Do not edit manually.

[SYSTEM]
DEVICE_MODEL=ACSC-V2
FIRMWARE_VER=1.0.3

[NETWORK]
DHCP_ENABLED=true

[SECURITY]
# Unique device key for API authentication
AUTH_KEY="acsc{binwalkisgod!}"
```

Ngay lập tức, chúng ta thấy một dòng `AUTH_KEY` chứa một chuỗi có định dạng của một flag. Đây chính là API Key mà chúng ta cần tìm.

**Flag:** `acsc{binwalkisgod!}`

---

### Cách tiếp cận thay thế (Sử dụng Binwalk)

Một cách tiếp cận nhanh hơn và hiệu quả hơn đối với các thử thách firmware là sử dụng công cụ `binwalk`. `binwalk` có khả năng tự động nhận diện và trích xuất các lớp file hệ thống và file nén lồng nhau.

Chỉ cần một lệnh duy nhất:
```bash
# -e: extract (trích xuất)
# -M: Matryoshka (trích xuất đệ quy)
$ binwalk -eM smart_firmware.img
```
Lệnh này sẽ tự động thực hiện các bước:
1.  Nhận diện và giải nén `gzip`.
2.  Nhận diện và giải nén file `tar` bên trong.
3.  Tạo một thư mục `_smart_firmware.img.extracted` chứa kết quả cuối cùng.

Sau đó, chúng ta cũng sẽ tìm đến file `etc/device.conf` bên trong thư mục được trích xuất để lấy flag. Tên của flag "binwalkisgod!" cũng là một gợi ý về công cụ mạnh mẽ này.

### Kết luận

Thử thách này kiểm tra kỹ năng cơ bản về phân tích file và firmware. Bằng cách sử dụng các công cụ dòng lệnh tiêu chuẩn của Linux như `file`, `gzip`, `tar` hoặc công cụ chuyên dụng như `binwalk`, người chơi có thể dễ dàng trích xuất hệ thống file và tìm thấy thông tin nhạy cảm được lưu trữ trong file cấu hình.