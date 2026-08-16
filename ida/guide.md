# Hướng dẫn sử dụng IDA (Interactive Disassembler) – Từ cơ bản đến nâng cao

> Tài liệu này là một cẩm nang thực hành chi tiết về IDA (IDA Free / IDA Home / IDA Pro) của Hex-Rays.
> Nội dung bao gồm: cài đặt, giao diện, điều hướng, phân tích tĩnh, kiểu dữ liệu, decompiler,
> debugger, patching, IDC, IDAPython, plugin, chế độ headless và các quy trình phân tích thực tế.
>
> **Lưu ý pháp lý:** Dịch ngược (reverse engineering) chỉ nên thực hiện trên phần mềm bạn có quyền
> phân tích: phần mềm của chính bạn, bài CTF/crackme, mẫu mã độc trong môi trường nghiên cứu được
> phép, hoặc trong phạm vi luật pháp và giấy phép sử dụng cho phép. Hãy tôn trọng giấy phép của
> chính IDA – chỉ dùng bản có bản quyền hợp lệ hoặc bản IDA Free.

---

## Mục lục

1. [Giới thiệu về IDA](#1-giới-thiệu-về-ida)
2. [Các phiên bản và giấy phép](#2-các-phiên-bản-và-giấy-phép)
3. [Cài đặt và cấu hình ban đầu](#3-cài-đặt-và-cấu-hình-ban-đầu)
4. [Kiến thức nền tảng cần có](#4-kiến-thức-nền-tảng-cần-có)
5. [Mở file và quá trình phân tích tự động](#5-mở-file-và-quá-trình-phân-tích-tự-động)
6. [Tổng quan giao diện](#6-tổng-quan-giao-diện)
7. [Điều hướng trong IDA](#7-điều-hướng-trong-ida)
8. [Disassembly View và Graph View](#8-disassembly-view-và-graph-view)
9. [Định nghĩa code và dữ liệu](#9-định-nghĩa-code-và-dữ-liệu)
10. [Đổi tên và chú thích](#10-đổi-tên-và-chú-thích)
11. [Tham chiếu chéo (Cross-references)](#11-tham-chiếu-chéo-cross-references)
12. [Hàm và Stack Frame](#12-hàm-và-stack-frame)
13. [Kiểu dữ liệu, Struct, Enum và Local Types](#13-kiểu-dữ-liệu-struct-enum-và-local-types)
14. [Hex-Rays Decompiler](#14-hex-rays-decompiler)
15. [Tìm kiếm](#15-tìm-kiếm)
16. [FLIRT, Type Libraries và Lumina](#16-flirt-type-libraries-và-lumina)
17. [Patching – Sửa đổi chương trình](#17-patching--sửa-đổi-chương-trình)
18. [Debugger](#18-debugger)
19. [Ngôn ngữ script IDC](#19-ngôn-ngữ-script-idc)
20. [IDAPython](#20-idapython)
21. [Viết và cài đặt Plugin](#21-viết-và-cài-đặt-plugin)
22. [Chế độ dòng lệnh, batch và idalib](#22-chế-độ-dòng-lệnh-batch-và-idalib)
23. [Phân tích các kiến trúc khác](#23-phân-tích-các-kiến-trúc-khác)
24. [Quy trình phân tích thực tế (walkthrough)](#24-quy-trình-phân-tích-thực-tế-walkthrough)
25. [Kỹ thuật chống phân tích và cách xử lý](#25-kỹ-thuật-chống-phân-tích-và-cách-xử-lý)
26. [Mẹo, thủ thuật và lỗi thường gặp](#26-mẹo-thủ-thuật-và-lỗi-thường-gặp)
27. [Bảng phím tắt tổng hợp](#27-bảng-phím-tắt-tổng-hợp)
28. [Thuật ngữ](#28-thuật-ngữ)
29. [Tài liệu tham khảo và lộ trình học](#29-tài-liệu-tham-khảo-và-lộ-trình-học)

---

## 1. Giới thiệu về IDA

### 1.1. IDA là gì?

IDA (viết tắt của **Interactive DisAssembler**) là công cụ dịch ngược mã máy được phát triển
bởi công ty **Hex-Rays** (Bỉ). IDA nhận đầu vào là một file nhị phân (ví dụ `.exe`, `.dll`,
`.so`, file ELF, Mach-O, firmware thô...) và chuyển mã máy thành hợp ngữ (assembly) mà con
người có thể đọc được. Với plugin **Hex-Rays Decompiler**, IDA còn có thể dựng lại mã giả
(pseudocode) tương tự ngôn ngữ C.

Điểm làm nên tên tuổi của IDA là chữ **Interactive** – tương tác. IDA không chỉ disassemble
một lần rồi xong; người phân tích liên tục bổ sung tri thức (đổi tên hàm, đặt kiểu dữ liệu,
định nghĩa struct, thêm comment...) và IDA lập tức lan truyền những thông tin đó ra toàn bộ
cơ sở dữ liệu. Càng phân tích, kết quả càng "sạch" và dễ đọc hơn.

### 1.2. IDA dùng để làm gì?

| Lĩnh vực | Ứng dụng cụ thể |
|---|---|
| Phân tích mã độc | Hiểu hành vi malware, trích xuất IOC, viết chữ ký phát hiện |
| Nghiên cứu lỗ hổng | Tìm bug trong phần mềm đóng mã nguồn, phân tích bản vá (patch diffing) |
| CTF / Crackme | Giải các bài reverse engineering trong các cuộc thi |
| Kiểm thử tương thích | Hiểu giao thức/định dạng file không có tài liệu để làm phần mềm tương thích |
| Firmware & IoT | Phân tích firmware nhúng (ARM, MIPS, PowerPC, AVR...) |
| Phát triển phần mềm | Debug bản release không có symbol, kiểm tra output của compiler |
| Pháp chứng số | Phân tích công cụ được dùng trong sự cố an ninh |

### 1.3. Lịch sử ngắn gọn

- IDA được Ilfak Guilfanov viết ra từ đầu những năm 1990, ban đầu là ứng dụng DOS.
- Sau đó được phân phối thương mại qua DataRescue, rồi Hex-Rays tiếp quản từ khoảng 2008.
- Hex-Rays Decompiler ra đời năm 2007, trở thành tính năng "đinh" của IDA.
- IDAPython được tích hợp chính thức, cho phép tự động hóa bằng Python.
- Các phiên bản 7.x chuyển sang 64-bit, Python 3 và API mới.
- Từ IDA 9.0, các bản `ida` và `ida64` được hợp nhất thành một chương trình duy nhất, bổ sung
  **idalib** (dùng IDA như thư viện), và mô hình giấy phép/phiên bản được tổ chức lại.

> Thông tin phiên bản thay đổi theo thời gian. Luôn kiểm tra trang chính thức
> `https://hex-rays.com` để biết phiên bản mới nhất và tính năng của từng gói.

### 1.4. So sánh với các công cụ khác

| Tiêu chí | IDA Pro | Ghidra | Binary Ninja | radare2 / Cutter |
|---|---|---|---|---|
| Giá | Thương mại (có bản Free) | Miễn phí, mã nguồn mở | Thương mại (có bản Free) | Miễn phí, mã nguồn mở |
| Decompiler | Hex-Rays (rất mạnh) | Có sẵn, mạnh | Có sẵn (HLIL) | r2ghidra / r2dec |
| Số kiến trúc hỗ trợ | Rất nhiều | Nhiều | Khá nhiều | Nhiều |
| Script | IDC, Python | Java, Python (Jython/PyGhidra) | Python, C++, Rust | r2pipe (nhiều ngôn ngữ) |
| Debugger tích hợp | Có, nhiều backend | Có (từ 10.x) | Có | Có |
| Hệ sinh thái plugin | Rất lớn, lâu đời | Lớn, đang phát triển | Đang phát triển | Trung bình |
| Độ "chuẩn công nghiệp" | Rất cao | Cao | Trung bình – cao | Trung bình |

Không có công cụ nào "tốt nhất tuyệt đối". Nhiều chuyên gia dùng kết hợp: IDA cho phân tích
chính, Ghidra để đối chiếu decompiler, BinDiff/Diaphora để so sánh phiên bản.

---

## 2. Các phiên bản và giấy phép

### 2.1. Các gói phổ biến

| Gói | Đặc điểm chính | Phù hợp với |
|---|---|---|
| **IDA Free** | Miễn phí, dùng phi thương mại, giới hạn kiến trúc (chủ yếu x86/x64), có decompiler đám mây cho x86/x64 | Người mới, sinh viên, học tập |
| **IDA Home** | Giá thấp, dùng cá nhân/phi thương mại, chọn một số kiến trúc, có decompiler | Người đam mê, CTF player |
| **IDA Pro** | Bản đầy đủ, dùng thương mại, nhiều kiến trúc, có thể mua thêm decompiler cho từng kiến trúc | Chuyên gia, doanh nghiệp |
| **IDA Classroom / Education** | Giấy phép cho trường học | Giảng dạy |

> Chi tiết các gói (tên gói, giá, kiến trúc kèm theo) đã thay đổi nhiều lần qua các phiên bản.
> Hãy đọc bảng so sánh trên trang Hex-Rays trước khi mua.

### 2.2. Những giới hạn thường gặp của IDA Free

- Không dùng cho mục đích thương mại.
- Hỗ trợ ít bộ xử lý (processor module) hơn.
- Decompiler thường là bản cloud (gửi mã lên máy chủ Hex-Rays để decompile), chỉ cho một số kiến trúc.
- Một số tính năng như một số loader, debugger backend, SDK có thể bị hạn chế.
- IDAPython có trong các bản gần đây nhưng có thể có giới hạn tùy phiên bản.

### 2.3. File cơ sở dữ liệu của IDA

IDA không sửa file gốc. Mọi kết quả phân tích được lưu trong một **cơ sở dữ liệu (database)**:

| Đuôi file | Ý nghĩa |
|---|---|
| `.idb` | Database cho chương trình 32-bit (phiên bản cũ dùng `ida.exe`) |
| `.i64` | Database cho chương trình 64-bit (hoặc mọi chương trình trong IDA 9.x) |
| `.id0` | Phần B-tree chứa phần lớn thông tin (tên, comment, xref...) – file tạm khi DB đang mở |
| `.id1` | Cờ (flags) mô tả từng byte của chương trình – file tạm |
| `.id2` | Dữ liệu bổ sung – file tạm |
| `.nam` | Danh sách tên – file tạm |
| `.til` | Thư viện kiểu (type library) cục bộ – file tạm |
| `.$$$` | Dữ liệu tạm khi DB chưa đóng đúng cách |

Khi bạn đóng IDA và chọn "Pack database", các file tạm được nén gộp lại thành `.idb`/`.i64`.
Nếu IDA bị crash, các file `.id0/.id1/...` vẫn còn và IDA có thể hỏi bạn khôi phục.

**Khuyến nghị:** Luôn sao lưu file `.i64` thường xuyên (hoặc dùng tính năng snapshot – xem phần 26).

---

## 3. Cài đặt và cấu hình ban đầu

### 3.1. Yêu cầu hệ thống

- Hệ điều hành: Windows 64-bit, Linux 64-bit, macOS (Intel và Apple Silicon tùy phiên bản).
- RAM: tối thiểu 4 GB, khuyến nghị 16 GB trở lên khi phân tích binary lớn (vài chục MB).
- Ổ cứng: database có thể lớn gấp nhiều lần file gốc; nên dành vài GB trống.
- Python 3 (64-bit) để dùng IDAPython – phiên bản Python tương thích tùy bản IDA.

### 3.2. Cài đặt trên Windows

1. Tải bộ cài từ trang khách hàng Hex-Rays (bản Pro/Home) hoặc trang tải IDA Free.
2. Chạy file cài đặt, chọn thư mục (mặc định `C:\Program Files\IDA Professional 9.x` hoặc tương tự).
3. Nếu bộ cài hỏi về Python, chọn cài/kết nối với Python 3 đã có trên máy.
4. Kích hoạt giấy phép theo hướng dẫn (file license hoặc máy chủ license, tùy gói).
5. Mở IDA lần đầu, chấp nhận điều khoản.

### 3.3. Cài đặt trên Linux

```bash
# Cấp quyền thực thi cho bộ cài
chmod +x ida-pro_9x_x64linux.run

# Chạy bộ cài (giao diện đồ họa hoặc chế độ text)
./ida-pro_9x_x64linux.run

# Chạy IDA sau khi cài
~/idapro-9.x/ida
```

Một số thư viện Qt/X11 có thể cần cài thêm:

```bash
sudo apt install libxcb-xinerama0 libxkbcommon-x11-0 libxcb-icccm4 \
                 libxcb-image0 libxcb-keysyms1 libxcb-render-util0
```

### 3.4. Cài đặt trên macOS

1. Mở file `.dmg` hoặc `.app.zip`, kéo IDA vào `Applications`.
2. Lần đầu mở, macOS có thể chặn – vào **System Settings → Privacy & Security** để cho phép.
3. Với debugger trên macOS, cần cấp quyền debug và có thể phải ký lại (codesign) debug server.

### 3.5. Cấu hình IDAPython

IDA đi kèm công cụ `idapyswitch` để chọn bản Python mà IDA sẽ dùng:

```bash
# Windows (chạy trong thư mục cài IDA)
idapyswitch.exe

# Linux / macOS
./idapyswitch
```

Công cụ sẽ liệt kê các bản Python tìm thấy; chọn số tương ứng. Sau đó kiểm tra trong IDA:

```python
# Gõ vào ô Output (chế độ Python)
import sys
print(sys.version)
```

Cài thêm thư viện Python cho IDA dùng chính interpreter đó:

```bash
python -m pip install --user capstone keystone-engine
```

### 3.6. Thư mục người dùng và file cấu hình

| Hệ điều hành | Thư mục người dùng (IDAUSR) |
|---|---|
| Windows | `%APPDATA%\Hex-Rays\IDA Pro` |
| Linux / macOS | `~/.idapro` |

Trong thư mục này bạn có thể tạo:

```
IDAUSR/
├── plugins/          # plugin cá nhân (.py hoặc .dll/.so/.dylib)
├── cfg/              # file cấu hình ghi đè (ida.cfg, hexrays.cfg...)
├── idapythonrc.py    # script Python chạy mỗi khi IDA khởi động
├── loaders/          # loader tùy chỉnh
├── procs/            # processor module tùy chỉnh
└── themes/           # giao diện màu
```

Có thể đặt biến môi trường `IDAUSR` để trỏ tới thư mục khác (hữu ích khi dùng nhiều cấu hình).

### 3.7. Các tùy chỉnh nên làm ngay

**Options → General → Disassembly:**

- Bật **Line prefixes (graph)** để thấy địa chỉ trong Graph View.
- Bật **Number of opcode bytes** = 8 hoặc 10 để xem byte máy cạnh lệnh.
- Bật **Auto comments** nếu bạn mới học assembly (IDA chú thích ý nghĩa lệnh).

**Options → General → Cross-references:**

- Tăng **Number of displayed xrefs** lên 10–20 để thấy nhiều xref hơn ngay trong listing.

**Options → General → Graph:**

- Tăng **Max number of nodes** nếu hàm lớn không hiển thị được ở dạng graph.

**Options → Colors:** chọn theme tối nếu muốn (IDA có sẵn theme "darcula" và "dark").

**Options → Font:** dùng font monospace dễ đọc như Consolas, JetBrains Mono, Fira Code.

Ví dụ ghi đè cấu hình bằng file `IDAUSR/cfg/idauser.cfg` (cú pháp giống `ida.cfg`):

```
// Hiển thị 8 byte opcode
OPCODE_BYTES            = 8
// Hiển thị nhiều xref hơn
SHOW_XREFS              = 20
// Giới hạn số node trong graph
GRAPH_MAX_NODES         = 5000
```

> Tên chính xác của các khóa có thể khác nhau giữa các phiên bản; mở `cfg/ida.cfg` trong thư mục
> cài đặt để xem danh sách khóa hợp lệ và chỉ sao chép phần cần thay đổi.

---

## 4. Kiến thức nền tảng cần có

IDA là công cụ mạnh, nhưng hiệu quả phụ thuộc vào nền tảng của người dùng. Phần này tóm tắt
những kiến thức tối thiểu.

### 4.1. Hệ số và biểu diễn dữ liệu

- **Hệ 16 (hex):** IDA mặc định hiển thị số dạng hex với hậu tố `h`, ví dụ `0FFh`, `401000h`.
- **Little-endian:** x86/x64 lưu byte thấp trước. Giá trị `0x12345678` trong bộ nhớ là `78 56 34 12`.
- **Số có dấu:** dùng bù 2 (two's complement). `0xFFFFFFFF` = `-1` khi hiểu là `int32`.

| Kiểu | Kích thước | Ký hiệu trong IDA |
|---|---|---|
| byte | 1 byte | `db` |
| word | 2 byte | `dw` |
| dword | 4 byte | `dd` |
| qword | 8 byte | `dq` |
| oword / xmmword | 16 byte | `xmmword` |
| float | 4 byte | `dd` (float) |
| double | 8 byte | `dq` (double) |
| tbyte | 10 byte | `dt` |

### 4.2. Thanh ghi x86-64

| Thanh ghi 64-bit | 32-bit | 16-bit | 8-bit | Công dụng thường gặp |
|---|---|---|---|---|
| RAX | EAX | AX | AL | Giá trị trả về của hàm |
| RBX | EBX | BX | BL | Thanh ghi đa dụng, callee-saved |
| RCX | ECX | CX | CL | Tham số 1 (Windows x64), bộ đếm vòng lặp |
| RDX | EDX | DX | DL | Tham số 2 (Windows x64), tham số 3 (SysV) |
| RSI | ESI | SI | SIL | Tham số 2 (SysV), nguồn sao chép chuỗi |
| RDI | EDI | DI | DIL | Tham số 1 (SysV), đích sao chép chuỗi |
| RSP | ESP | SP | SPL | Con trỏ ngăn xếp (stack pointer) |
| RBP | EBP | BP | BPL | Con trỏ khung (frame pointer) |
| R8 – R15 | R8D – R15D | R8W – R15W | R8B – R15B | Tham số bổ sung, đa dụng |
| RIP | EIP | IP | – | Con trỏ lệnh |
| RFLAGS | EFLAGS | FLAGS | – | Cờ trạng thái (ZF, CF, SF, OF...) |

### 4.3. Quy ước gọi hàm (calling conventions)

| Quy ước | Nền tảng | Tham số | Ai dọn stack | Trả về |
|---|---|---|---|---|
| `__cdecl` | x86 (C mặc định) | Đẩy lên stack từ phải sang trái | Hàm gọi (caller) | EAX |
| `__stdcall` | x86 WinAPI | Stack, phải sang trái | Hàm được gọi (callee) | EAX |
| `__fastcall` | x86 | ECX, EDX, phần còn lại trên stack | Callee | EAX |
| `__thiscall` | x86 C++ (MSVC) | `this` trong ECX, còn lại trên stack | Callee | EAX |
| Microsoft x64 | Windows x64 | RCX, RDX, R8, R9, sau đó stack; có 32 byte "shadow space" | Caller | RAX |
| System V AMD64 | Linux/macOS x64 | RDI, RSI, RDX, RCX, R8, R9, sau đó stack | Caller | RAX |
| AAPCS | ARM 32-bit | R0–R3, sau đó stack | Caller | R0 |
| AAPCS64 | ARM64 | X0–X7, sau đó stack | Caller | X0 |

Hiểu calling convention giúp bạn đặt đúng prototype hàm (phím `Y`), từ đó decompiler cho
kết quả chính xác.

### 4.4. Stack frame điển hình (x86 32-bit)

```asm
push    ebp             ; lưu frame pointer cũ
mov     ebp, esp        ; thiết lập frame mới
sub     esp, 20h        ; cấp phát 0x20 byte cho biến cục bộ
...
mov     eax, [ebp+8]    ; tham số thứ nhất
mov     [ebp-4], eax    ; biến cục bộ thứ nhất
...
mov     esp, ebp        ; (hoặc lệnh leave)
pop     ebp
retn
```

Sơ đồ bộ nhớ:

```
Địa chỉ cao
+------------------+
| tham số 2        |  [ebp+0Ch]
| tham số 1        |  [ebp+8]
| địa chỉ trả về   |  [ebp+4]
| EBP cũ           |  [ebp]      <- EBP
| biến cục bộ 1    |  [ebp-4]
| biến cục bộ 2    |  [ebp-8]
| ...              |
+------------------+  <- ESP
Địa chỉ thấp
```

IDA tự động nhận diện cấu trúc này và đặt tên như `arg_0`, `var_4`. Xem phần 12.

### 4.5. Định dạng file thực thi

**PE (Windows):**

- DOS header (`MZ`), PE header (`PE\0\0`), Optional Header (ImageBase, AddressOfEntryPoint...).
- Section: `.text` (code), `.rdata` (dữ liệu chỉ đọc, import), `.data`, `.rsrc` (tài nguyên), `.reloc`.
- Import Address Table (IAT): danh sách hàm DLL được gọi.
- Export table: hàm mà DLL công khai.
- TLS callbacks: code chạy trước entry point (hay bị malware lợi dụng).

**ELF (Linux, Android, nhiều thiết bị nhúng):**

- ELF header (`\x7fELF`), Program headers (segment), Section headers.
- Section: `.text`, `.rodata`, `.data`, `.bss`, `.plt`, `.got`, `.init_array`, `.fini_array`.
- Hàm thư viện được gọi qua PLT/GOT.

**Mach-O (macOS, iOS):**

- Load commands, segment `__TEXT`, `__DATA`, `__LINKEDIT`.
- Có thể là "fat/universal binary" chứa nhiều kiến trúc – IDA sẽ hỏi bạn chọn kiến trúc nào.

### 4.6. Các lệnh assembly hay gặp nhất

| Lệnh | Ý nghĩa | Ví dụ |
|---|---|---|
| `mov` | Sao chép giá trị | `mov eax, [ebp+8]` |
| `lea` | Tính địa chỉ (không đọc bộ nhớ) | `lea eax, [ebx+ecx*4]` |
| `push` / `pop` | Đẩy / lấy giá trị trên stack | `push eax` |
| `call` / `ret` | Gọi hàm / trở về | `call sub_401000` |
| `add` / `sub` | Cộng / trừ | `sub esp, 10h` |
| `imul` / `mul` | Nhân có dấu / không dấu | `imul eax, ecx` |
| `idiv` / `div` | Chia | `idiv ecx` |
| `and` / `or` / `xor` / `not` | Phép bit | `xor eax, eax` (gán 0) |
| `shl` / `shr` / `sar` | Dịch bit | `shr eax, 2` |
| `rol` / `ror` | Xoay bit | `rol eax, 5` (hay gặp trong hash) |
| `cmp` | So sánh (trừ, chỉ đặt cờ) | `cmp eax, 10h` |
| `test` | AND, chỉ đặt cờ | `test eax, eax` |
| `jmp` | Nhảy không điều kiện | `jmp short loc_401020` |
| `jz`/`je`, `jnz`/`jne` | Nhảy nếu bằng / khác | `jz loc_401050` |
| `jg`, `jl`, `jge`, `jle` | So sánh có dấu | `jl loc_...` |
| `ja`, `jb`, `jae`, `jbe` | So sánh không dấu | `ja loc_...` |
| `movzx` / `movsx` | Mở rộng không dấu / có dấu | `movzx eax, byte ptr [ecx]` |
| `cmovcc` | Mov có điều kiện | `cmovz eax, ebx` |
| `setcc` | Đặt byte theo cờ | `setz al` |
| `rep movsb` | Sao chép khối bộ nhớ (memcpy) | |
| `rep stosb` | Ghi khối bộ nhớ (memset) | |
| `cpuid`, `rdtsc` | Thông tin CPU, đếm xung | Hay gặp trong anti-debug/anti-VM |
| `syscall` / `int 80h` | Gọi hệ thống | Linux |

---

## 5. Mở file và quá trình phân tích tự động

### 5.1. Mở file mới

Có ba cách:

1. Kéo thả file vào cửa sổ IDA.
2. **File → Open** (`Ctrl+O`).
3. Từ dòng lệnh: `ida path/to/binary`.

Màn hình **Quick Start** khi khởi động có các nút **New**, **Go** (mở IDA trống), **Previous**
(mở database gần đây).

### 5.2. Hộp thoại "Load a new file"

Đây là bước quan trọng nhất – chọn sai sẽ cho kết quả phân tích sai.

| Tùy chọn | Mô tả |
|---|---|
| **Loader** | IDA tự nhận dạng: `Portable executable for AMD64 (PE)`, `ELF64 for x86-64`, `Binary file`... |
| **Processor type** | Kiến trúc CPU. Với file thô (binary file), bạn phải chọn thủ công (ví dụ `ARM Little-endian`). |
| **Loading segment / offset** | Địa chỉ nạp với file thô (ví dụ firmware nạp tại `0x08000000`). |
| **Analysis: Enabled** | Bật phân tích tự động. Hầu như luôn bật. |
| **Indicator enabled** | Hiển thị trạng thái phân tích ở thanh dưới. |
| **Kernel options 1/2/3** | Tinh chỉnh thuật toán phân tích (tạo hàm, nhận dạng switch, ...) |
| **Processor options** | Tùy chọn riêng cho kiến trúc (ví dụ ARM: chế độ Thumb mặc định) |
| **Load resources** | Nạp section tài nguyên của PE |
| **Manual load** | Cho phép chọn từng section để nạp |
| **Create segments / imports segment** | Tạo segment riêng cho bảng import |
| **Load as dynamic library / Fill segment gaps** | Một số tùy chọn đặc thù cho loader |

**Mẹo:** Với file PE/ELF bình thường, chỉ cần nhấn **OK**. Khi IDA hỏi có tải file PDB (Windows)
hoặc thông tin debug DWARF (Linux) không, hãy chọn **Yes** nếu có – symbol sẽ làm việc phân tích
dễ hơn rất nhiều.

### 5.3. Quá trình auto-analysis

Sau khi nạp, IDA chạy các bước tự động:

1. Tạo segment theo header của file.
2. Bắt đầu từ entry point và các export, disassemble theo **luồng điều khiển** (recursive descent),
   không phải tuần tự từng byte (linear sweep).
3. Tạo hàm, nhận diện prologue/epilogue.
4. Áp dụng chữ ký **FLIRT** để nhận diện hàm thư viện chuẩn (`memcpy`, `printf`, CRT...).
5. Áp dụng **type library** để gán kiểu cho hàm import (ví dụ `CreateFileW`).
6. Phân tích stack frame, xác định biến cục bộ và tham số.
7. Nhận diện chuỗi, bảng switch, bảng con trỏ.
8. Lan truyền kiểu và tên.

Thanh trạng thái ở góc dưới bên trái hiển thị:

| Trạng thái | Ý nghĩa |
|---|---|
| `AU: idle` | Đã phân tích xong |
| `AU: busy` | Đang phân tích |
| `AU: disabled` | Phân tích tự động đã bị tắt |

Chờ cho đến khi `AU: idle` rồi mới làm việc nghiêm túc hoặc chạy script, vì kết quả có thể còn
thay đổi.

Thanh màu ngang phía trên (**navigation band**) cho biết tổng quan file:

| Màu (mặc định) | Ý nghĩa |
|---|---|
| Xanh dương đậm | Code thông thường (hàm do người viết) |
| Xanh lam nhạt / xanh ngọc | Hàm thư viện được FLIRT nhận diện |
| Hồng | Hàm/dữ liệu external (import) |
| Xám | Dữ liệu |
| Nâu / vàng nâu | Vùng chưa được khám phá (unexplored) |
| Đỏ | Code nhưng không thuộc hàm nào |
| Mũi tên vàng | Vị trí con trỏ hiện tại |

Nếu thấy rất nhiều vùng nâu (unexplored) hoặc rất ít code, có thể file đã bị **pack/obfuscate**
(xem phần 25).

### 5.4. Phân tích lại

- **Options → General → Analysis → Reanalyze program**: phân tích lại toàn bộ.
- Chọn một vùng, nhấn `C` để ép thành code, hoặc dùng script `ida_auto.plan_and_wait(start, end)`.

### 5.5. Mở lại database đã lưu

Mở trực tiếp file `.i64`/`.idb`. Không cần file gốc (dữ liệu đã nằm trong database), trừ khi bạn
muốn debug hoặc apply patch.

Khi đóng (**File → Close** hoặc tắt cửa sổ), IDA hỏi:

| Lựa chọn | Ý nghĩa |
|---|---|
| Don't pack database | Giữ các file tạm `.id0/.id1/...`, mở lại nhanh nhưng tốn chỗ |
| Pack database (Store) | Gộp thành một file không nén |
| Pack database (Deflate) | Gộp và nén – khuyến nghị |
| Collect garbage | Dọn dữ liệu thừa trước khi đóng |
| DON'T SAVE the database | Bỏ mọi thay đổi kể từ lần lưu gần nhất |

Nhấn `Ctrl+W` để lưu nhanh database trong khi đang làm việc.

---

## 6. Tổng quan giao diện

### 6.1. Các cửa sổ chính

| Cửa sổ | Mở bằng | Công dụng |
|---|---|---|
| **IDA View-A** (Disassembly) | `View → Open subviews → Disassembly` | Hiển thị mã assembly, dạng text hoặc graph |
| **Pseudocode-A** | `F5` / `Tab` | Mã giả C từ decompiler |
| **Hex View-1** | `View → Open subviews → Hex dump` | Hiển thị byte thô, đồng bộ với disassembly |
| **Functions** | `Shift+F3` (tùy phiên bản) | Danh sách hàm |
| **Names** | `Shift+F4` | Tất cả tên đã đặt (hàm, biến, nhãn) |
| **Strings** | `Shift+F12` | Danh sách chuỗi trong file |
| **Imports** | `View → Open subviews → Imports` | Hàm được import |
| **Exports** | `View → Open subviews → Exports` | Hàm được export, entry point |
| **Segments** | `Shift+F7` | Danh sách segment/section |
| **Local Types** | `Shift+F1` | Struct, union, enum, typedef cục bộ |
| **Structures / Enums** | `Shift+F9` / `Shift+F10` (các bản cũ) | Trình sửa struct/enum riêng (trong IDA 9 gộp vào Local Types) |
| **Type libraries** | `Shift+F11` | Thư viện kiểu đã nạp |
| **Signatures** | `Shift+F5` | Chữ ký FLIRT đã áp dụng |
| **Cross references** | `X` hoặc `Ctrl+X` | Ai tham chiếu tới mục hiện tại |
| **Output** | `View → Output window` | Log, kết quả script, ô nhập lệnh Python/IDC |
| **Problems** | `View → Open subviews → Problems` | Danh sách vấn đề trong phân tích |
| **Bookmarks / Marked positions** | `Ctrl+M` | Vị trí đã đánh dấu |
| **Call graph / Proximity** | `View → Open subviews → Proximity browser` | Quan hệ gọi hàm |
| **Microcode / Ctree** | Plugin hoặc menu decompiler | Xem biểu diễn trung gian (nâng cao) |

### 6.2. Bố cục mặc định

```
+---------------------------------------------------------------------+
| Menu | Toolbar                                                       |
| Navigation band (thanh màu tổng quan file)                           |
+-------------+-------------------------------------------------------+
| Functions   | IDA View-A | Pseudocode-A | Hex View-1 | Structures... |
| window      |                                                       |
|             |                (vùng làm việc chính)                  |
|             |                                                       |
+-------------+                                                       |
| Graph       |                                                       |
| overview    |                                                       |
+-------------+-------------------------------------------------------+
| Output window                              [Python ▼] > ________    |
+---------------------------------------------------------------------+
| AU: idle | Down | Disk: 50GB                                         |
+---------------------------------------------------------------------+
```

### 6.3. Tùy biến bố cục

- Kéo thả tab để sắp xếp, đặt hai cửa sổ cạnh nhau (ví dụ disassembly bên trái, pseudocode bên phải).
- **Windows → Save desktop**: lưu bố cục, có thể đặt làm mặc định.
- **Windows → Reset desktop**: khôi phục bố cục mặc định khi lỡ làm rối.
- Có thể mở nhiều IDA View (IDA View-B, C...) để xem nhiều vị trí cùng lúc.

### 6.4. Đồng bộ hóa (synchronization)

Chuột phải trên tab → **Synchronize with** → chọn cửa sổ khác. Ví dụ đồng bộ Hex View với
Disassembly: khi bạn di chuyển trong disassembly, hex view tự nhảy tới đúng byte. Pseudocode
cũng có thể đồng bộ để dòng C tương ứng được tô sáng.

### 6.5. Cửa sổ Output và ô lệnh

Ở cuối cửa sổ Output có ô nhập lệnh. Nút bên trái cho phép chọn ngôn ngữ **IDC** hoặc **Python**.

```python
# Một số lệnh nhanh hữu ích
here()                          # địa chỉ con trỏ hiện tại (ida_kernwin.get_screen_ea())
hex(here())
idc.get_func_name(here())
print(len(list(idautils.Functions())))   # số hàm
```

### 6.6. Chọn kiểu tô sáng

Click vào một thanh ghi hoặc tên, IDA sẽ tô sáng mọi lần xuất hiện của nó trên màn hình – rất
hữu ích để theo dõi luồng dữ liệu trong hàm. Có thể tắt/bật trong Options.

### 6.7. Command palette

Từ IDA 7.x trở đi có **Command palette** (`Ctrl+Shift+P`) – gõ tên thao tác để thực hiện mà
không cần nhớ phím tắt. Rất tiện cho người mới.

---

## 7. Điều hướng trong IDA

### 7.1. Di chuyển cơ bản

| Thao tác | Phím |
|---|---|
| Nhảy tới địa chỉ hoặc tên | `G` |
| Quay lại vị trí trước | `Esc` |
| Tiến tới (sau khi đã quay lại) | `Ctrl+Enter` |
| Nhảy tới tham chiếu dưới con trỏ | `Enter` hoặc double-click |
| Nhảy tới hàm (danh sách) | `Ctrl+P` |
| Nhảy tới entry point | `Ctrl+E` |
| Nhảy tới segment | `Ctrl+S` |
| Nhảy theo tên | `Ctrl+L` |
| Nhảy tới hàm tiếp theo / trước đó | `Ctrl+↓` / `Ctrl+↑` (tùy cấu hình) |
| Nhảy tới vị trí đã đánh dấu | `Ctrl+M` |
| Đánh dấu vị trí | `Alt+M` |
| Nhảy tới offset trong file | `Jump → Jump to file offset` |

### 7.2. Hộp thoại Jump (G)

Trong ô nhập của `G`, bạn có thể gõ:

- Địa chỉ hex: `401000` hoặc `0x401000`.
- Tên: `main`, `WinMain`, `sub_401230`.
- Biểu thức: `401000+20`, `main+0x15`.
- Biến tạm của debugger khi đang debug: tên thanh ghi như `rip`, `rsp`.

### 7.3. Lịch sử điều hướng

IDA lưu lịch sử nhảy giống trình duyệt web. Hãy tập thói quen: **Enter** để đi sâu vào hàm,
**Esc** để quay ra. Đây là cách di chuyển nhanh nhất.

### 7.4. Đánh dấu (bookmarks)

- `Alt+M`: đặt bookmark tại vị trí hiện tại kèm mô tả, ví dụ "giải mã cấu hình C2".
- `Ctrl+M`: mở danh sách bookmark để nhảy tới.
- Bookmark được lưu trong database.

### 7.5. Lọc danh sách

Mọi cửa sổ danh sách (Functions, Strings, Names...) đều hỗ trợ:

- Gõ trực tiếp để tìm kiếm nhanh (quick filter) – `Ctrl+F` để bật ô lọc.
- Click tiêu đề cột để sắp xếp (ví dụ sắp xếp hàm theo kích thước – hàm lớn thường quan trọng).
- Chuột phải → **Modify filters** để lọc theo điều kiện phức tạp, hỗ trợ regex.
- Có thể copy toàn bộ danh sách (`Ctrl+Insert` hoặc chuột phải → Copy all).

### 7.6. Chiến lược tìm điểm bắt đầu

Khi mở một binary lạ, đừng đọc từ entry point một cách tuần tự. Hãy:

1. **Strings (Shift+F12):** tìm chuỗi thú vị (thông báo lỗi, URL, đường dẫn registry, "password",
   "correct", "wrong"...). Double-click → `X` để tìm hàm dùng chuỗi đó.
2. **Imports:** xem chương trình dùng API gì. `CreateRemoteThread`, `VirtualAllocEx`,
   `CryptDecrypt`, `InternetOpenUrlA`, `socket`, `connect`... cho biết khả năng của chương trình.
3. **Exports:** với DLL, xem hàm nào được công khai.
4. **Functions:** sắp xếp theo kích thước hoặc số xref.
5. **Tìm `main`:** từ entry point, theo CRT startup tới lời gọi `main`/`WinMain`. Với ELF dùng glibc,
   tham số đầu tiên của `__libc_start_main` chính là địa chỉ `main`.

---

## 8. Disassembly View và Graph View

### 8.1. Chuyển đổi giữa hai chế độ

Nhấn **Space** trong IDA View để chuyển giữa **Text view** (dạng danh sách tuyến tính) và
**Graph view** (dạng sơ đồ khối).

### 8.2. Đọc một dòng trong Text view

```
.text:00401000 55                    push    ebp
.text:00401001 8B EC                 mov     ebp, esp
.text:00401003 83 EC 10              sub     esp, 10h
.text:00401006 8B 45 08              mov     eax, [ebp+arg_0]
```

| Thành phần | Ý nghĩa |
|---|---|
| `.text` | Tên segment |
| `00401000` | Địa chỉ ảo (virtual address) |
| `55` | Byte opcode (nếu bật hiển thị) |
| `push ebp` | Lệnh (mnemonic + operand) |
| `[ebp+arg_0]` | Operand đã được IDA đặt tên theo stack frame |

Các ký hiệu khác:

- Mũi tên bên trái thể hiện luồng nhảy: nét liền = nhảy không điều kiện, nét đứt = có điều kiện.
- `; CODE XREF: sub_401100+1A↑p` – comment tự động chỉ ra ai tham chiếu tới đây.
  - `p` = call (procedure), `j` = jump, `o` = offset, `r` = read, `w` = write.
  - `↑` / `↓` cho biết nguồn tham chiếu nằm phía trên / dưới.
- `loc_401020` – nhãn trong hàm; `sub_401000` – hàm chưa có tên; `unk_` – dữ liệu chưa rõ kiểu.

### 8.3. Tiền tố tên tự động

| Tiền tố | Ý nghĩa |
|---|---|
| `sub_` | Hàm (subroutine) |
| `loc_` | Nhãn code (đích nhảy) |
| `locret_` | Nhãn tại lệnh return |
| `off_` | Dữ liệu là con trỏ (offset) |
| `seg_` | Địa chỉ segment |
| `asc_` / `a` | Chuỗi ASCII (ví dụ `aHelloWorld`) |
| `byte_` | Dữ liệu 1 byte |
| `word_` | Dữ liệu 2 byte |
| `dword_` | Dữ liệu 4 byte |
| `qword_` | Dữ liệu 8 byte |
| `flt_` / `dbl_` | Float / double |
| `stru_` | Struct |
| `algn_` | Vùng căn lề (alignment) |
| `unk_` | Byte chưa xác định |
| `j_` | Hàm chỉ là một lệnh jmp tới hàm khác (thunk) |
| `nullsub_` | Hàm rỗng (chỉ có `ret`) |
| `__imp_` | Con trỏ import trong IAT |
| `def_` | Nhánh default của switch |
| `jpt_` | Bảng nhảy (jump table) của switch |

### 8.4. Graph view

Graph view biểu diễn hàm dưới dạng **basic block** (khối lệnh liên tục không có nhảy ở giữa) nối
bằng các cạnh:

| Màu cạnh | Ý nghĩa |
|---|---|
| Xanh lá | Nhánh khi điều kiện đúng (jump taken) |
| Đỏ | Nhánh khi điều kiện sai (fall-through) |
| Xanh dương | Nhảy không điều kiện |

Thao tác trong Graph view:

- Lăn chuột + `Ctrl` để phóng to/thu nhỏ; kéo nền để di chuyển.
- **Graph overview** (cửa sổ nhỏ) để thấy toàn cảnh hàm.
- Chuột phải trên khối → **Set node color** để tô màu khối đã phân tích.
- **Group nodes** (`Ctrl+G` trong một số bản): gom nhiều khối thành một để thu gọn hàm lớn.
- Double-click cạnh để nhảy tới khối nguồn/đích.
- `W` hoặc **Fit window**: thu cho vừa cửa sổ (tùy phiên bản).

### 8.5. Nhận diện cấu trúc điều khiển trong graph

**If – else:**

```
     [cmp eax, 0 / jz]
       /          \
  [then]        [else]
       \          /
        [tiếp tục]
```

**Vòng lặp:** có cạnh quay ngược lên khối phía trên (back edge). IDA vẽ cạnh này rõ ràng.

**Switch:** một khối có rất nhiều cạnh đi ra, thường có lệnh như:

```asm
cmp     eax, 7
ja      def_401050          ; default
jmp     ds:jpt_401050[eax*4] ; jump table
```

IDA thường tự nhận diện và comment `switch 8 cases`. Nếu không nhận diện được, dùng
**Edit → Other → Specify switch idiom** để khai báo thủ công.

### 8.6. Proximity browser

**View → Open subviews → Proximity browser**: hiển thị đồ thị quan hệ gọi hàm quanh hàm hiện
tại. Dùng `+`/`-` trên các node để mở rộng/thu gọn. Hữu ích để hiểu kiến trúc chương trình.

---

## 9. Định nghĩa code và dữ liệu

IDA cho phép bạn "nói" với nó rằng một vùng byte là code, chuỗi, số, mảng hay struct. Đây là
phần cốt lõi của chữ "interactive".

### 9.1. Các phím cơ bản

| Phím | Thao tác |
|---|---|
| `C` | Chuyển thành **code** (disassemble tại đây) |
| `D` | Chuyển thành **data**; nhấn lặp lại để xoay vòng `db → dw → dd → dq` |
| `A` | Chuyển thành **chuỗi** ASCII (C string) |
| `U` | **Undefine** – trả về byte thô chưa xác định |
| `*` | Tạo **mảng** (array) |
| `P` | Tạo **hàm** (procedure) tại vị trí hiện tại |
| `O` | Hiểu operand là **offset** (con trỏ) |
| `Ctrl+O` | Offset với base tùy chọn |
| `H` | Hiển thị số dạng **hex/decimal** (đảo qua lại) |
| `B` | Hiển thị dạng **nhị phân** |
| `R` | Hiển thị dạng **ký tự** (`'A'`) |
| `Q` | Hiển thị dạng **hex** |
| `M` | Thay số bằng **hằng enum** (symbolic constant) |
| `T` | Hiểu operand là **offset trong struct** |
| `_` (gạch dưới) | Đổi dấu số (signed/unsigned) – tùy phiên bản |
| `~` | Đảo bit (bitwise negate) để hiển thị |
| `Alt+A` | Chọn **kiểu chuỗi** (UTF-16, Pascal...) |
| `Alt+D` | Chọn **kiểu dữ liệu** (bao gồm float, double) |
| `Alt+Q` | Áp dụng **struct** cho vùng dữ liệu (các bản cũ) |
| `Y` | Đặt **kiểu C** cho mục hiện tại (cách hiện đại để áp dụng struct/kiểu) |

### 9.2. Ví dụ: sửa vùng bị phân tích sai

Giả sử IDA hiểu nhầm một bảng dữ liệu thành code:

```asm
.data:00405000                 add     [eax], al
.data:00405002                 add     [eax], al
.data:00405004                 inc     ecx
```

Thao tác:

1. Đặt con trỏ tại `00405000`, nhấn `U` để undefine.
2. Nhấn `D` ba lần để thành `dd` (dword).
3. Nhấn `*`, nhập số phần tử (ví dụ 16) để tạo mảng.
4. Nếu đây là bảng con trỏ, nhấn `O` để hiểu từng phần tử là offset.

Kết quả:

```asm
.data:00405000 off_405000      dd offset sub_401200, offset sub_401250, offset sub_4012A0
.data:00405000                 dd offset sub_401300, ...
```

### 9.3. Code bị bỏ sót

Đôi khi IDA để nguyên một vùng byte nâu (unexplored) dù đó là code – ví dụ hàm chỉ được gọi gián
tiếp qua con trỏ. Cách xử lý:

1. Đặt con trỏ tại đầu vùng, nhấn `C`.
2. Nếu code hợp lệ, nhấn `P` để tạo hàm.
3. Nếu `P` báo lỗi, kiểm tra: lệnh cuối có phải `ret`? Có lệnh nào bị decode sai không?

### 9.4. Tạo mảng (dialog `*`)

| Trường | Ý nghĩa |
|---|---|
| Array size | Số phần tử |
| Items on a line | Số phần tử hiển thị trên một dòng (0 = tự động) |
| Element print width | Độ rộng mỗi phần tử |
| Use "dup" construct | Gộp giá trị lặp lại (`100 dup(0)`) |
| Signed elements | Hiển thị có dấu |
| Display indexes | Hiển thị chỉ số trong comment |
| Create as array | Bỏ chọn để tách thành nhiều mục riêng |

### 9.5. Chuỗi

- `A`: chuỗi C kết thúc bằng `\0`.
- `Alt+A`: chọn kiểu khác:
  - C (8-bit), C (16-bit / UTF-16LE – rất phổ biến trên Windows), C (32-bit),
  - Pascal (có byte độ dài ở đầu), chuỗi có độ dài 2 byte / 4 byte...
- Trong cửa sổ Strings, chuột phải → **Setup** để chọn kiểu chuỗi được quét và độ dài tối thiểu.
  Nếu không thấy chuỗi Unicode, hãy bật **Unicode C-style (16 bits)**.

### 9.6. Thay đổi kích thước một mục

Nếu IDA tạo một mục dữ liệu quá lớn, che mất dữ liệu phía sau, dùng `U` để undefine rồi tạo lại
với kích thước đúng.

### 9.7. Segment register và chế độ ARM/Thumb

Trên ARM, cùng một byte có thể là lệnh ARM (32-bit) hoặc Thumb (16/32-bit). IDA dùng một
"segment register" ảo tên `T`:

- Nhấn `Alt+G`, đặt `T = 1` để chuyển vùng sang Thumb, `T = 0` cho ARM.
- Sau đó nhấn `U` rồi `C` để disassemble lại.

---

## 10. Đổi tên và chú thích

### 10.1. Đổi tên (N)

Đặt con trỏ trên tên hàm, biến, nhãn hoặc địa chỉ, nhấn `N`:

| Tùy chọn trong dialog | Ý nghĩa |
|---|---|
| Local name | Tên chỉ có ý nghĩa trong hàm hiện tại (nhãn) |
| Include in names list | Hiển thị trong cửa sổ Names |
| Public name | Đánh dấu là tên public |
| Autogenerated name | Tên do IDA tự sinh (sẽ bị ghi đè khi phân tích lại) |
| Weak name | Tên yếu |
| Create name anyway | Tạo dù trùng tên (IDA sẽ thêm hậu tố) |

**Quy ước đặt tên nên dùng** (giúp database dễ đọc):

- Hàm: động từ + danh từ: `decrypt_config`, `send_beacon`, `parse_header`, `check_license`.
- Biến toàn cục: `g_` + tên: `g_server_list`, `g_xor_key`.
- Hàm chưa chắc chắn: thêm `maybe_` hoặc `?_`: `maybe_rc4_init`.
- Hàm wrapper: `w_` hoặc `wrap_`: `wrap_malloc`.
- Giữ tên do symbol cung cấp, không đổi trừ khi cần.

IDA hiển thị tên do người dùng đặt bằng màu khác với tên tự động, giúp bạn biết chỗ nào đã phân tích.

### 10.2. Các loại comment

| Phím | Loại | Đặc điểm |
|---|---|---|
| `:` | Regular comment | Hiển thị ở cuối dòng, chỉ tại vị trí đó |
| `;` | Repeatable comment | Hiển thị tại vị trí đó **và** ở mọi nơi tham chiếu tới nó |
| `Insert` | Anterior lines | Dòng chú thích phía **trên** lệnh |
| `Shift+Insert` | Posterior lines | Dòng chú thích phía **dưới** lệnh |
| `/` (trong Pseudocode) | Comment trong mã giả | Gắn với dòng C |
| Function comment | `:` hoặc `;` khi đặt con trỏ tại tên hàm | Hiển thị ở đầu hàm |

**Repeatable comment** rất mạnh: đặt comment `; Mã hóa RC4 với key 16 byte` tại hàm
`sub_401500`, mọi lệnh `call sub_401500` trong chương trình đều hiển thị comment này.

Ví dụ kết hợp:

```asm
.text:00401500 ; ========== Khởi tạo kết nối C2 ==========   <- anterior line (Insert)
.text:00401500 connect_c2      proc near                  ; Trả về socket hoặc -1  <- function comment
.text:00401500                 push    ebp
.text:00401501                 mov     ebp, esp
.text:00401503                 push    1BBh               ; cổng 443  <- regular comment (:)
```

### 10.3. Tô màu

- Chuột phải → **Edit → Other → Color instruction** (hoặc chọn màu cho dòng/hàm).
- Trong Functions window, có thể đổi màu cả hàm để đánh dấu đã phân tích xong / cần xem lại.
- Script tô màu tất cả lệnh `call` (xem phần IDAPython).

### 10.4. Đổi tên thanh ghi (register variable)

Trong một hàm, nếu `esi` luôn giữ con trỏ tới một object, bạn có thể đặt tên cho thanh ghi:
đặt con trỏ trên `esi`, nhấn `N`, đặt tên `pConfig`. Tên này chỉ có hiệu lực trong phạm vi chỉ
định (thường là cả hàm hoặc một khoảng địa chỉ).

### 10.5. Undo / Redo

Từ IDA 7.3, IDA hỗ trợ **Undo** (`Ctrl+Z`) và **Redo** (`Ctrl+Shift+Z`) cho hầu hết thao tác
trên database. Trước đó không có undo – nên các bài viết cũ thường khuyên sao lưu thường xuyên.
Dù có undo, việc sao lưu vẫn được khuyến khích.

---

## 11. Tham chiếu chéo (Cross-references)

Cross-reference (xref) là thông tin "ai dùng cái gì". Đây có lẽ là tính năng được dùng nhiều nhất
khi dịch ngược.

### 11.1. Loại xref

| Loại | Ký hiệu | Ý nghĩa |
|---|---|---|
| Code – Call near/far | `p` | Lệnh `call` tới địa chỉ |
| Code – Jump | `j` | Lệnh nhảy tới địa chỉ |
| Code – Ordinary flow | (ẩn) | Lệnh này chạy tiếp sang lệnh sau |
| Data – Offset | `o` | Địa chỉ được lấy làm con trỏ (`push offset aHello`) |
| Data – Read | `r` | Đọc giá trị (`mov eax, dword_405000`) |
| Data – Write | `w` | Ghi giá trị (`mov dword_405000, eax`) |
| Data – Informational | `i` | Thông tin khác |

### 11.2. Xem xref

- Đặt con trỏ trên tên/địa chỉ, nhấn `X` → hộp thoại **xrefs to** (ai tham chiếu tới đây).
- `Ctrl+X` trong một số ngữ cảnh / bản cũ: xrefs to; `Ctrl+J` hoặc menu: **xrefs from** (từ đây đi đâu).
- Trong Pseudocode, `X` trên biến/hàm cũng hoạt động.
- **View → Open subviews → Cross references**: cửa sổ xref cố định, cập nhật theo con trỏ.

Hộp thoại xref có các cột: Direction (Up/Down), Type (p/j/r/w/o), Address, Text (lệnh tại đó).

### 11.3. Ứng dụng điển hình

1. **Từ chuỗi đến hàm:** Strings → double-click chuỗi `"Invalid license"` → `X` → nhảy tới hàm kiểm tra license.
2. **Từ API đến hành vi:** Imports → `RegSetValueExW` → `X` → thấy mọi chỗ ghi registry (cơ chế persistence?).
3. **Theo dấu biến toàn cục:** `X` trên `dword_40A010` → xem ai ghi (`w`) và ai đọc (`r`) – biết biến này là cờ gì.
4. **Đi ngược call chain:** từ hàm đáng chú ý, `X` liên tục để tìm đường đi từ `main`.

### 11.4. Xref graph

- **View → Graphs → Xrefs to / Xrefs from** (hoặc chuột phải → *Xrefs graph to/from*): vẽ đồ thị
  tham chiếu, có tùy chọn độ sâu đệ quy.
- **Function calls** (`Ctrl+Alt+F` tùy phiên bản): danh sách hàm gọi và được gọi.

### 11.5. Xref thủ công

Với lời gọi gián tiếp (`call eax`, `call [rbx+18h]`), IDA không biết đích. Bạn có thể thêm xref:

- **Edit → Other → Set callee address** (hoặc `Alt+F11` tùy bản) – khai báo đích của lời gọi gián tiếp.
- Hoặc dùng script: `ida_xref.add_cref(frm, to, ida_xref.fl_CN)`.

Sau khi thêm, cả xref và decompiler đều hưởng lợi.

---

## 12. Hàm và Stack Frame

### 12.1. Thao tác với hàm

| Phím | Thao tác |
|---|---|
| `P` | Tạo hàm tại con trỏ |
| `Alt+P` | Sửa thuộc tính hàm (tên, địa chỉ bắt đầu/kết thúc, cờ) |
| `E` | Đặt điểm kết thúc hàm tại con trỏ |
| `Delete` (trong Functions window) | Xóa định nghĩa hàm (không xóa code) |
| `Ctrl+K` | Mở cửa sổ stack frame của hàm (các bản cũ; IDA 9 hiển thị frame như một kiểu struct) |
| `Alt+K` | Thay đổi giá trị stack pointer tại lệnh hiện tại |
| `Y` (trên tên hàm) | Đặt prototype hàm |

### 12.2. Dialog sửa hàm (Alt+P)

| Trường / cờ | Ý nghĩa |
|---|---|
| Start / End address | Phạm vi hàm |
| Local variables area | Kích thước vùng biến cục bộ |
| Saved registers | Số byte thanh ghi được lưu |
| Purged bytes | Số byte tham số mà hàm tự dọn (stdcall) |
| Does not return | Hàm không trả về (ví dụ `exit`, `abort`) – rất quan trọng cho phân tích luồng |
| Far function | Hàm far (16-bit) |
| Library func | Hàm thư viện |
| Static func | Hàm static |
| BP based frame | Hàm dùng EBP/RBP làm frame pointer |
| BP equals to SP | Frame pointer bằng stack pointer |
| Fuzzy SP | SP không xác định chính xác |
| Outlined code | Code bị compiler "outline" |

**Ví dụ quan trọng:** nếu một hàm báo lỗi rồi gọi `ExitProcess`, nhưng IDA không biết hàm đó
không trả về, nó sẽ coi code phía sau là một phần của hàm → hàm bị sai ranh giới. Đánh dấu
**Does not return** cho hàm báo lỗi sẽ sửa vấn đề này.

### 12.3. Function chunks (tail)

Compiler tối ưu có thể tách hàm thành nhiều khúc rời rạc. IDA gọi là **function chunks** hoặc
**tails**:

- Comment `; START OF FUNCTION CHUNK FOR sub_401000` đánh dấu một tail.
- Thêm tail thủ công: chọn vùng code → **Edit → Functions → Append function tail**.
- Xóa tail: **Edit → Functions → Remove function tail**.

### 12.4. Stack frame

IDA phân tích các truy cập `[ebp+X]`, `[esp+X]`, `[rsp+X]` để dựng **stack frame**, với các thành phần:

```
-00000010 var_10          dd ?
-0000000C var_C           dd ?
-00000008 var_8           dd ?
-00000004 var_4           dd ?
+00000000  s              db 4 dup(?)     ; saved registers
+00000004  r              db 4 dup(?)     ; return address
+00000008 arg_0           dd ?
+0000000C arg_4           dd ?
```

- `var_*`: biến cục bộ (offset âm).
- `s`: thanh ghi đã lưu; `r`: địa chỉ trả về.
- `arg_*`: tham số (offset dương).

Bạn có thể đổi tên (`N`), đổi kiểu (`Y` hoặc `D`), tạo mảng (`*`) cho các mục trong frame. Ví dụ
buffer 256 byte trên stack thường xuất hiện là nhiều `var_` rời rạc; gộp chúng thành
`char buffer[256]` sẽ làm cả disassembly lẫn pseudocode rõ ràng hơn.

### 12.5. Stack pointer và lỗi "sp-analysis failed"

Bật **Options → General → Disassembly → Stack pointer** để hiển thị giá trị SP tương đối ở mỗi
dòng:

```
.text:00401000 000                 push    ebp
.text:00401001 004                 mov     ebp, esp
.text:00401003 004                 sub     esp, 10h
.text:00401006 014                 push    esi
```

Nếu SP không cân bằng khi tới `ret`, IDA đánh dấu đỏ và decompiler báo **"sp-analysis failed"**
hoặc **"positive sp value"**. Nguyên nhân thường gặp:

- IDA không biết số byte mà một hàm callee tự dọn (stdcall) – sửa prototype hàm callee.
- Lời gọi gián tiếp tới hàm stdcall.
- Code bị obfuscate có thao tác stack lạ.

Cách sửa: đặt con trỏ tại lệnh gây lệch, nhấn `Alt+K`, nhập giá trị thay đổi SP đúng. Hoặc
sửa prototype của hàm được gọi để IDA tính đúng.

### 12.6. Prototype hàm

Đặt con trỏ trên tên hàm, nhấn `Y`, nhập prototype C:

```c
int __cdecl check_password(const char *input, int length);
BOOL __stdcall decrypt_buffer(BYTE *buf, DWORD size, const BYTE *key);
__int64 __fastcall parse_packet(struct packet *pkt, unsigned int flags);
void __noreturn fatal_error(const char *msg);
```

Một số từ khóa đặc biệt IDA hiểu:

| Từ khóa | Ý nghĩa |
|---|---|
| `__noreturn` | Hàm không trả về |
| `__usercall` | Quy ước tùy chỉnh, chỉ định thanh ghi cho từng tham số |
| `__userpurge` | Như usercall nhưng callee dọn stack |
| `__spoils<eax,ecx>` | Danh sách thanh ghi bị hàm làm thay đổi |
| `__hidden` | Tham số ẩn (ví dụ `this` hoặc giá trị trả về struct) |
| `__return_ptr` | Con trỏ tới vùng nhận struct trả về |
| `__struct_ptr` | Tham số struct truyền bằng con trỏ |
| `__format("printf")` hoặc `__attribute__((format(printf,1,2)))` | Hàm kiểu printf (tùy phiên bản) |

**`__usercall`** rất hữu ích với code tối ưu hoặc viết tay:

```c
// Tham số 1 ở EAX, tham số 2 ở EDX, trả về ở EAX
int __usercall my_hash@<eax>(const char *str@<eax>, int seed@<edx>);

// Trả về trong cặp EDX:EAX
__int64 __usercall get_value@<edx:eax>(int idx@<ecx>);
```

### 12.7. Thunk và wrapper

- **Thunk**: hàm chỉ gồm `jmp` tới hàm khác. IDA thường đặt tiền tố `j_`.
- **Wrapper**: hàm gọi một API với tham số cố định. Đổi tên ngay (`w_CreateFileW`) để tiết kiệm thời gian.

---

## 13. Kiểu dữ liệu, Struct, Enum và Local Types

### 13.1. Tại sao kiểu dữ liệu quan trọng?

So sánh pseudocode trước và sau khi định nghĩa struct:

**Trước:**

```c
int __fastcall sub_140001200(__int64 a1)
{
  if ( *(_DWORD *)(a1 + 16) > 0x400u )
    return 0;
  sub_140001500(*(_QWORD *)(a1 + 8), *(unsigned int *)(a1 + 16));
  *(_BYTE *)(a1 + 20) = 1;
  return 1;
}
```

**Sau:**

```c
int __fastcall process_packet(packet_t *pkt)
{
  if ( pkt->length > 0x400 )
    return 0;
  decrypt_buffer(pkt->data, pkt->length);
  pkt->is_decrypted = 1;
  return 1;
}
```

Chỉ cần định nghĩa một struct và đặt kiểu cho tham số, toàn bộ hàm trở nên dễ hiểu.

### 13.2. Local Types (Shift+F1)

Từ IDA 9.0, **Local Types** là nơi trung tâm để quản lý mọi kiểu: struct, union, enum, typedef,
prototype. Các cửa sổ Structures/Enums riêng biệt của bản cũ được hợp nhất vào đây.

Thao tác trong Local Types:

| Phím / thao tác | Ý nghĩa |
|---|---|
| `Insert` | Thêm kiểu mới bằng khai báo C |
| `Ctrl+E` | Sửa kiểu dạng C |
| Double-click | Mở trình sửa struct dạng bảng (tùy phiên bản) |
| `Delete` | Xóa kiểu |
| Chuột phải → Synchronize to idb | Đồng bộ kiểu ra database (bản cũ) |

Ví dụ thêm kiểu (Insert):

```c
typedef struct packet_t {
    unsigned int   magic;        // 0x00
    unsigned int   flags;        // 0x04
    unsigned char *data;         // 0x08
    unsigned int   length;       // 0x10
    unsigned char  is_decrypted; // 0x14
    unsigned char  pad[3];       // 0x15
} packet_t;

enum command_id {
    CMD_PING     = 1,
    CMD_EXEC     = 2,
    CMD_UPLOAD   = 3,
    CMD_DOWNLOAD = 4,
    CMD_EXIT     = 0xFF,
};
```

### 13.3. Parse file header C (Ctrl+F9)

**File → Load file → Parse C header file** (`Ctrl+F9`): nạp toàn bộ một file `.h` vào Local
Types. Hữu ích khi bạn có header của thư viện hoặc tự viết header cho dự án phân tích.

Lưu ý: parser của IDA không hỗ trợ đầy đủ C++ hiện đại (template phức tạp...). Hãy đơn giản hóa
header trước khi nạp. Có thể cấu hình include path và macro trong
**Options → Compiler**.

### 13.4. Trình sửa struct dạng bảng (phong cách cũ)

Trong các bản trước 9.0 (cửa sổ Structures, `Shift+F9`):

| Phím | Thao tác |
|---|---|
| `Insert` | Tạo struct mới |
| `D` | Thêm field / đổi kích thước field (byte/word/dword) |
| `A` | Field là chuỗi |
| `*` | Field là mảng |
| `N` | Đổi tên field |
| `Y` | Đặt kiểu C cho field |
| `U` | Xóa field |
| `Ctrl+E` | Sửa kích thước struct |
| `Ctrl+X` | Xref tới struct/field |

### 13.5. Áp dụng struct

- **Trên dữ liệu toàn cục:** đặt con trỏ tại địa chỉ, nhấn `Y`, gõ `packet_t` (hoặc `Alt+Q` ở bản cũ).
- **Trên operand:** với `mov eax, [esi+10h]`, đặt con trỏ trên operand, nhấn `T`, chọn
  `packet_t.length` → lệnh hiển thị `mov eax, [esi+packet_t.length]`.
- **Trong pseudocode:** nhấn `Y` trên biến, gõ `packet_t *`.

### 13.6. Tự động tạo struct trong decompiler

Trong Pseudocode, chuột phải trên một biến con trỏ → **Create new struct type**. IDA phân tích
các truy cập `*(a1 + offset)` và tạo struct với các field tương ứng. Sau đó bạn chỉ cần đổi tên
field. (Plugin như HexRaysPyTools mở rộng tính năng này mạnh hơn.)

### 13.7. Enum và hằng số

Khi thấy số "ma thuật" như `0x80000000` trong lời gọi `CreateFileW`, đặt con trỏ, nhấn `M` để
chọn hằng enum phù hợp (`GENERIC_READ`). IDA có sẵn rất nhiều enum từ type library Windows.

Ví dụ trước và sau:

```asm
push    80000000h        ->    push    GENERIC_READ
push    3                ->    push    OPEN_EXISTING
```

Enum dạng **bitfield** (cờ OR với nhau) cũng được hỗ trợ: tạo enum, đánh dấu là bitfield, IDA
sẽ hiển thị `FILE_SHARE_READ | FILE_SHARE_WRITE`.

### 13.8. Union

Dùng khi cùng một vùng nhớ được hiểu theo nhiều cách (ví dụ một message có nhiều dạng):

```c
union payload_u {
    struct { int x; int y; } point;
    char text[64];
    unsigned int raw[16];
};
```

Trong pseudocode, nếu IDA chọn sai thành viên union, nhấn `Alt+Y` để chọn thành viên khác.

### 13.9. Kiểu C++ và vtable

Code C++ thường gọi hàm ảo qua vtable:

```c
(*(void (__fastcall **)(__int64))(*(_QWORD *)a1 + 24LL))(a1);
```

Cách làm rõ:

1. Tạo struct vtable:

```c
struct CObject;
struct CObject_vtbl {
    void (__fastcall *destructor)(struct CObject *self);
    int  (__fastcall *init)(struct CObject *self);
    void (__fastcall *reset)(struct CObject *self);
    int  (__fastcall *process)(struct CObject *self);
};
struct CObject {
    struct CObject_vtbl *vtbl;
    int refcount;
    char *name;
};
```

2. Đặt kiểu `CObject *` cho `a1`. Pseudocode sẽ thành `a1->vtbl->process(a1);`.

Với binary MSVC có **RTTI**, IDA (hoặc plugin như ClassInformer) có thể khôi phục tên lớp và
vtable tự động. Với GCC/Clang, demangling tên (`_ZN7CObject7processEv`) cho biết tên lớp/phương thức.
Bật demangle trong **Options → Demangled names**.

### 13.10. Type library (.til)

Type library là tập hợp kiểu và prototype hàm đã biên dịch sẵn (ví dụ `mssdk_win10` cho Windows
SDK, `gnulnx_x64` cho glibc). Mở **Shift+F11 → Insert** để nạp thêm thư viện. Ví dụ phân tích
driver Windows nên nạp `ntddk`/`wdk` để có các kiểu kernel như `DRIVER_OBJECT`, `IRP`.

---

## 14. Hex-Rays Decompiler

### 14.1. Giới thiệu

Hex-Rays Decompiler chuyển mã máy thành pseudocode giống C. Có các decompiler riêng cho từng
kiến trúc: x86, x64, ARM, ARM64, PowerPC, MIPS, RISC-V... (tùy gói giấy phép). IDA Free dùng
decompiler cloud cho x86/x64.

> Pseudocode là **mã giả**, không phải mã nguồn gốc. Tên biến, cấu trúc vòng lặp, kiểu dữ liệu
> đều là phỏng đoán. Luôn kiểm chứng với disassembly khi gặp chỗ đáng ngờ.

### 14.2. Mở pseudocode

- `F5`: decompile hàm hiện tại, mở cửa sổ Pseudocode.
- `Tab`: chuyển qua lại giữa disassembly và pseudocode tại vị trí tương ứng.
- **File → Produce file → Create C file** (`Ctrl+F5`): decompile toàn bộ chương trình ra file `.c`.

### 14.3. Phím tắt trong Pseudocode

| Phím | Thao tác |
|---|---|
| `N` | Đổi tên biến / hàm / field |
| `Y` | Đổi kiểu biến hoặc prototype hàm |
| `/` | Thêm comment cho dòng |
| `Insert` | Comment block |
| `X` | Xref tới mục dưới con trỏ |
| `Tab` | Sang disassembly |
| `Esc` | Quay lại |
| `H` | Hiển thị số dạng hex/decimal |
| `R` | Hiển thị số dạng ký tự |
| `M` | Chọn hằng enum |
| `_` (hoặc menu) | Đổi dấu hằng số |
| `\` | Ẩn/hiện cast (`(_DWORD *)`) |
| `=` | Map biến này sang biến khác (gộp hai biến thực chất là một) |
| `Alt+Y` | Chọn thành viên union |
| `Shift+Del` | Xóa tham số khỏi prototype hàm (tùy phiên bản / menu) |
| `Ctrl+Shift+R` hoặc chuột phải → Reset pointer type | Đặt lại kiểu |
| `-` / `+` (trên khối) | Thu gọn / mở rộng khối `if`, `while` |
| `F5` | Refresh (decompile lại) |
| `Ctrl+Alt+...` | Nhiều thao tác khác qua chuột phải |

Menu chuột phải còn có: **Split variable**, **Unsplit**, **Force call type**, **Set call type**,
**Jump to xref**, **Convert to struct ***, **Create new struct type**, **Mark as decompiled**,
**Edit indented comment**, **Copy to assembly**...

### 14.4. Quy trình "làm sạch" pseudocode

Một hàm vừa decompile thường trông như sau:

```c
__int64 __fastcall sub_140001A30(__int64 a1, unsigned int a2, __int64 a3)
{
  unsigned int v3; // ebx
  __int64 v4; // rdi
  __int64 result; // rax
  unsigned int i; // [rsp+20h] [rbp-18h]

  v3 = a2;
  v4 = a1;
  for ( i = 0; i < v3; ++i )
    *(_BYTE *)(v4 + i) ^= *(_BYTE *)(a3 + i % 0x10);
  result = 1LL;
  return result;
}
```

Các bước làm sạch:

1. **Đổi tên hàm** (`N` trên tên): `xor_decrypt`.
2. **Đặt prototype** (`Y` trên tên): `__int64 __fastcall xor_decrypt(unsigned char *buf, unsigned int size, const unsigned char *key);`
3. **Đổi tên biến** (`N`): `v3` → `size_copy`, hoặc dùng `=` để map `v3` vào `size` nếu chúng là một.
4. **Ẩn cast** (`\`) nếu cần.
5. **Thêm comment** (`/`): "XOR với key 16 byte lặp lại".

Kết quả:

```c
__int64 __fastcall xor_decrypt(unsigned __int8 *buf, unsigned int size, const unsigned __int8 *key)
{
  unsigned int i;

  for ( i = 0; i < size; ++i )
    buf[i] ^= key[i % 0x10];   // XOR với key 16 byte lặp lại
  return 1;
}
```

### 14.5. Các vấn đề thường gặp và cách xử lý

| Vấn đề | Dấu hiệu | Cách xử lý |
|---|---|---|
| Thiếu tham số | Hàm dùng thanh ghi chưa khởi tạo, xuất hiện biến lạ | Sửa prototype, thêm tham số hoặc dùng `__usercall` |
| Thừa tham số | Prototype có `a4`, `a5` không dùng | Sửa prototype bằng `Y`, bỏ tham số |
| Sai kiểu trả về | `return` giá trị vô nghĩa | Đặt `void` hoặc kiểu đúng |
| `sp-analysis failed` | Không decompile được | Sửa stack pointer (`Alt+K`) hoặc prototype callee |
| `JUMPOUT(0x...)` | Decompiler không hiểu nhảy ra ngoài hàm | Sửa ranh giới hàm, thêm function tail, hoặc vùng là code obfuscate |
| `__asm { ... }` | Lệnh không decompile được | Bình thường với lệnh đặc biệt (cpuid, rdtsc, in/out) |
| `MEMORY[0x...]` | Truy cập địa chỉ tuyệt đối | Tạo segment/biến tại địa chỉ đó hoặc đặt kiểu |
| Biến bị tách đôi | Hai biến cho cùng một thứ | Dùng `=` (map variable) |
| Một biến dùng cho hai mục đích | Tên biến không hợp lý | **Split variable** |
| Vòng lặp lạ, `goto` nhiều | Control flow phức tạp | Kiểm tra code obfuscate, thử tắt một số tối ưu trong hexrays.cfg |
| Hàm "noreturn" sai | Code sau lời gọi biến mất | Bỏ cờ noreturn của hàm đó (`Alt+P`) và refresh |
| Chuỗi hiển thị dạng số | `v5 = 0x6C6C6548;` | Nhấn `R` để thấy `'lleH'` – stack string |
| Hằng số trong `.data` có thể bị đổi | Decompiler coi là hằng | Đặt segment là writable, hoặc bỏ `const` |

### 14.6. Stack strings

Malware hay xây chuỗi trên stack để tránh bị phát hiện bằng lệnh `strings`:

```c
v6[0] = 'k';
v6[1] = 'e';
v6[2] = 'r';
v6[3] = 'n';
...
```

Hoặc dạng gộp: `*(_QWORD *)v6 = 0x32336C656E72656BLL;` → nhấn `R` để xem `'23lenrek'`
(đảo ngược do little-endian, tức là `kernel32`). Đặt kiểu `char v6[16]` (phím `Y`) để IDA hiển
thị đẹp hơn. Plugin như FLOSS (ngoài IDA) hoặc script IDAPython có thể giải tự động.

### 14.7. Cấu hình decompiler

File `cfg/hexrays.cfg` (sao chép sang `IDAUSR/cfg/` để ghi đè). Một số tùy chọn:

| Tùy chọn | Ý nghĩa |
|---|---|
| `RIGHT_MARGIN` | Độ rộng dòng tối đa |
| `MAX_FUNCSIZE` | Kích thước hàm tối đa có thể decompile (KB) |
| `HEXOPTIONS` | Cờ bit điều khiển nhiều hành vi |
| `DEFAULT_RADIX` | Hệ số mặc định (0 = tự động, 16 = hex) |
| `COLLAPSE_LVARS` | Thu gọn khai báo biến |

Trong IDA: **Edit → Plugins → Hex-Rays Decompiler → Options** để chỉnh một số tùy chọn bằng GUI.

### 14.8. Microcode (nâng cao)

Decompiler hoạt động qua nhiều tầng biểu diễn trung gian gọi là **microcode** (các mức maturity
từ `MMAT_GENERATED` đến `MMAT_LVARS`), sau đó tạo **ctree** (cây cú pháp C). API cho phép can
thiệp vào từng tầng để viết plugin khử obfuscation (ví dụ plugin HRDevHelper để xem ctree, các
bài viết về deobfuscation bằng microcode). Đây là chủ đề nâng cao, cần đọc tài liệu SDK.

### 14.9. So sánh pseudocode với disassembly

Mở hai cửa sổ cạnh nhau và đồng bộ chúng: click một dòng C sẽ tô sáng các lệnh assembly tương
ứng. Đây là cách tốt để học cả assembly lẫn hiểu decompiler đang làm gì.

---

## Hướng dẫn giải bài

## Hướng dẫn ứng dụng IDA

## 15. Tìm kiếm

### 15.1. Các loại tìm kiếm

| Phím | Loại tìm kiếm | Ví dụ |
|---|---|---|
| `Alt+T` | Tìm **text** trong listing (bao gồm comment, tên) | `GetProcAddress`, `xor` |
| `Ctrl+T` | Tìm tiếp kết quả text | |
| `Alt+B` | Tìm **chuỗi byte** (binary) | `55 8B EC`, `"password"`, `E8 ?? ?? ?? ??` |
| `Ctrl+B` | Tìm tiếp binary | |
| `Alt+I` | Tìm **giá trị immediate** (hằng số trong lệnh) | `0x67452301` (MD5), `0x9E3779B9` (TEA) |
| `Ctrl+I` | Tìm tiếp immediate | |
| `Alt+C` | Tìm lệnh **code** tiếp theo | |
| `Ctrl+D` | Tìm **data** tiếp theo | |
| `Ctrl+U` | Tìm byte **unexplored** tiếp theo | |
| `Ctrl+V` | Tìm **lỗi** (problem) tiếp theo | |
| `Ctrl+A`... | Một số phím tùy phiên bản | |

Tùy chọn **Find all occurrences** trong dialog sẽ liệt kê mọi kết quả vào một cửa sổ riêng.

### 15.2. Tìm kiếm binary nâng cao

Trong `Alt+B`:

- Byte hex cách nhau bằng dấu cách: `48 8B 05`.
- Ký tự đại diện: `??` hoặc `?` cho byte bất kỳ (tùy phiên bản): `E8 ? ? ? ? 85 C0`.
- Chuỗi trong ngoặc kép: `"cmd.exe"`.
- Chọn **Unicode strings** để tìm chuỗi UTF-16.
- Chọn hướng tìm (lên/xuống), phân biệt hoa thường.

### 15.3. Tìm thuật toán mã hóa bằng hằng số

Nhiều thuật toán có hằng số đặc trưng. Dùng `Alt+I` hoặc `Alt+B`:

| Thuật toán | Hằng số đặc trưng |
|---|---|
| MD5 | `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476` |
| SHA-1 | Như MD5 + `0xC3D2E1F0` |
| SHA-256 | `0x6A09E667`, `0xBB67AE85`, `0x428A2F98` |
| CRC32 | `0xEDB88320` (đa thức đảo), bảng 256 phần tử |
| TEA / XTEA | `0x9E3779B9` (delta) |
| AES | S-box bắt đầu `63 7C 77 7B F2 6B 6F C5` |
| RC4 | Vòng lặp khởi tạo 0..255 (không có hằng số đặc biệt) |
| Base64 | Chuỗi `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` |
| FNV-1a | `0x811C9DC5` (offset basis 32-bit), `0x01000193` (prime) |
| djb2 | `5381` (`0x1505`) |
| ChaCha20 / Salsa20 | Chuỗi `"expand 32-byte k"` |

Plugin **findcrypt** (findcrypt-yara) tự động quét các hằng số này.

### 15.4. Tìm kiếm trong danh sách

Trong mọi cửa sổ danh sách, `Ctrl+F` mở ô lọc. Ví dụ trong Imports gõ `Crypt` để thấy mọi API
mã hóa; trong Strings gõ `http` để thấy URL.

---

## 16. FLIRT, Type Libraries và Lumina

### 16.1. FLIRT là gì?

**FLIRT** (Fast Library Identification and Recognition Technology) nhận diện hàm thư viện đã được
liên kết tĩnh vào chương trình (ví dụ `memcpy`, `strlen`, hàm CRT của MSVC, OpenSSL...) bằng cách
so khớp chuỗi byte đầu hàm với cơ sở dữ liệu chữ ký (`.sig`).

Lợi ích: thay vì phải phân tích hàng nghìn hàm thư viện, bạn chỉ tập trung vào code do tác giả viết.

### 16.2. Áp dụng chữ ký

1. Mở **View → Open subviews → Signatures** (`Shift+F5`).
2. Nhấn `Insert`, chọn chữ ký phù hợp (ví dụ `vc64rtf` cho MSVC x64 runtime).
3. Cột **#func** cho biết số hàm được nhận diện. Nếu là 0, chữ ký không phù hợp.

### 16.3. Tạo chữ ký FLIRT riêng

Khi chương trình liên kết tĩnh với thư viện không có sẵn chữ ký (ví dụ một phiên bản cụ thể của
libcurl), bạn có thể tự tạo bằng bộ công cụ **FLAIR** (tải từ trang Hex-Rays, dành cho khách hàng):

```bash
# 1. Tạo file pattern từ thư viện tĩnh (.lib cho COFF, .a cho ELF)
pcf libcurl.lib libcurl.pat        # COFF/OMF (.lib của MSVC)
pelf libcurl.a libcurl.pat         # ELF (.a của GCC)

# 2. Biên dịch pattern thành chữ ký
sigmake libcurl.pat libcurl.sig

# 3. Nếu có xung đột, sigmake tạo file libcurl.exc
#    Mở file .exc, xóa các dòng chú thích ở đầu file, đánh dấu hàm muốn giữ
#    (thêm '+' hoặc '-' ở đầu dòng), rồi chạy lại:
sigmake libcurl.pat libcurl.sig

# 4. Sao chép libcurl.sig vào thư mục sig/<kiến trúc>/ của IDA hoặc IDAUSR
```

Mẹo: biên dịch thư viện với cùng compiler và cờ tối ưu như binary mục tiêu để tăng tỉ lệ khớp.

### 16.4. Type libraries

Như đã nói ở phần 13.10, type library cung cấp prototype và kiểu. Kết hợp FLIRT + type library:
khi FLIRT nhận ra hàm `strcpy`, IDA lấy prototype `char *strcpy(char *dst, const char *src)` từ
type library và áp dụng, giúp decompiler hiển thị đúng tham số.

### 16.5. Lumina

**Lumina** là dịch vụ chia sẻ metadata hàm (tên, prototype, comment) của Hex-Rays:

- **Lumina → Pull all metadata**: hỏi máy chủ xem có ai đã đặt tên cho các hàm có cùng "băm" chưa.
- **Lumina → Push all metadata**: gửi tên/kiểu của bạn lên máy chủ.

Lưu ý bảo mật: Push sẽ gửi metadata (không phải toàn bộ binary) lên máy chủ. Với dự án nhạy cảm
(mẫu mã độc chưa công bố, phần mềm khách hàng), hãy cân nhắc chính sách của tổ chức trước khi push.
Một số tổ chức dùng máy chủ Lumina riêng.

### 16.6. Các nguồn chữ ký khác

- Chữ ký cộng đồng cho thư viện phổ biến (tìm trên GitHub với từ khóa "FLIRT signatures").
- Plugin như **Lumen** (máy chủ Lumina mã nguồn mở) hoặc các công cụ tạo chữ ký cho Rust/Go.
- Với Go: IDA các bản gần đây có hỗ trợ tốt hơn để khôi phục tên hàm từ `pclntab`; ngoài ra có
  script như GoReSym (công cụ ngoài) để trích xuất metadata.
- Với Rust: demangle tên `_ZN...` hoặc `_R...`, áp dụng chữ ký cho thư viện chuẩn của đúng phiên bản Rust.

---

## 17. Patching – Sửa đổi chương trình

### 17.1. Khi nào cần patch?

- Bỏ qua một kiểm tra để tiếp tục phân tích động (ví dụ bỏ anti-debug trong lab).
- Sửa lỗi trong phần mềm của chính bạn mà không có mã nguồn.
- Giải CTF/crackme.
- Thử nghiệm giả thuyết ("nếu nhánh này được thực thi thì sao?").

> Không dùng patching để vượt qua cơ chế bản quyền của phần mềm thương mại – việc đó vi phạm giấy
> phép và có thể vi phạm pháp luật.

### 17.2. Các thao tác patch

Menu **Edit → Patch program**:

| Thao tác | Mô tả |
|---|---|
| Change byte... | Sửa từng byte (tối đa 16 byte một lần) |
| Change word... | Sửa một word |
| Assemble... | Gõ lệnh assembly, IDA tự mã hóa (hỗ trợ tốt nhất với x86/x64) |
| Patched bytes | Danh sách mọi byte đã sửa (có thể revert) |
| Apply patches to input file... | Ghi các thay đổi vào file gốc (có tùy chọn tạo bản sao lưu) |

Trong Hex View cũng có thể nhấn `F2` để bật chế độ sửa trực tiếp, gõ byte mới, nhấn `F2` lần nữa
để xác nhận.

### 17.3. Ví dụ: đảo điều kiện nhảy

Bài crackme đơn giản:

```asm
.text:00401050                 call    check_serial
.text:00401055                 test    eax, eax
.text:00401057                 jz      short loc_401070     ; nhảy tới "Wrong serial"
.text:00401059                 push    offset aCorrect      ; "Correct!"
```

Patch:

1. Đặt con trỏ tại `00401057`.
2. **Edit → Patch program → Assemble**, gõ `jnz short loc_401070` hoặc `nop` hai lần.
3. Byte `74 17` (jz) đổi thành `75 17` (jnz) hoặc `90 90` (nop nop).
4. **Edit → Patch program → Apply patches to input file**, chọn tạo bản sao lưu.

Bảng opcode nhảy ngắn hữu ích:

| Lệnh | Opcode (short) | Lệnh đối | Opcode |
|---|---|---|---|
| `jz` / `je` | `74` | `jnz` / `jne` | `75` |
| `jb` / `jc` | `72` | `jae` / `jnc` | `73` |
| `jbe` | `76` | `ja` | `77` |
| `jl` | `7C` | `jge` | `7D` |
| `jle` | `7E` | `jg` | `7F` |
| `js` | `78` | `jns` | `79` |
| `jmp short` | `EB` | – | – |
| `nop` | `90` | – | – |

Lệnh nhảy near (32-bit offset) có dạng `0F 84` (jz), `0F 85` (jnz)...; `jmp near` là `E9`.

### 17.4. Patch bằng script

```python
import ida_bytes

ea = 0x401057
ida_bytes.patch_byte(ea, 0x75)          # jz -> jnz
ida_bytes.patch_bytes(ea, b"\x90\x90")  # hoặc NOP 2 byte

# Xem byte gốc trước khi patch
print(hex(ida_bytes.get_original_byte(ea)))
```

### 17.5. Lưu ý khi patch

- Lệnh mới phải có kích thước **bằng hoặc nhỏ hơn** lệnh cũ; phần thừa điền `nop`.
- Với file PE có chữ ký số, patch sẽ làm chữ ký mất hiệu lực.
- Một số chương trình kiểm tra checksum/toàn vẹn – patch có thể khiến chúng từ chối chạy.
- Với code relocatable, cẩn thận với các byte nằm trong bảng relocation – loader có thể ghi đè chúng.
- Plugin **Keypatch** (dùng Keystone) cho phép assemble nhiều kiến trúc hơn công cụ có sẵn.

---

## 18. Debugger

### 18.1. Các backend debugger

| Debugger | Mục đích |
|---|---|
| Local Windows debugger | Debug chương trình Windows trên cùng máy |
| Local Linux debugger | Debug ELF trên Linux |
| Local macOS debugger | Debug Mach-O trên macOS |
| Remote Windows / Linux / macOS debugger | Debug qua mạng, dùng debug server |
| Remote GDB debugger | Kết nối GDB stub: QEMU, OpenOCD, thiết bị nhúng, VMware |
| Windbg debugger | Dùng engine WinDbg, debug kernel Windows |
| Bochs debugger | Giả lập bằng Bochs (debug code nhỏ, shellcode, boot sector) |
| Android / iOS debugger | Debug ứng dụng di động qua debug server (tùy phiên bản) |

Chọn debugger qua **Debugger → Select debugger** hoặc dropdown trên toolbar.

> **An toàn:** Khi debug mã độc, chương trình **thực sự chạy**. Luôn dùng máy ảo cô lập, không
> kết nối mạng thật (hoặc dùng mạng giả lập như INetSim/FakeNet), có snapshot để khôi phục.

### 18.2. Phím tắt debugger

| Phím | Thao tác |
|---|---|
| `F9` | Bắt đầu / tiếp tục chạy (Continue) |
| `F2` | Đặt / xóa breakpoint |
| `F7` | Step into (đi vào hàm) |
| `F8` | Step over (bước qua hàm) |
| `Ctrl+F7` | Run until return (chạy tới khi hàm trả về) |
| `F4` | Run to cursor (chạy tới vị trí con trỏ) |
| `Ctrl+F2` | Terminate process (dừng chương trình) |
| `Ctrl+Alt+B` | Danh sách breakpoint |
| `Ctrl+N` | Đặt IP (instruction pointer) tại con trỏ |
| `Pause` (nút) | Tạm dừng tiến trình đang chạy |

### 18.3. Debug chương trình local

1. Chọn **Local Windows debugger** (hoặc Linux).
2. **Debugger → Process options**: thiết lập
   - Application: đường dẫn file thực thi,
   - Input file: file đầu vào (thường giống Application),
   - Directory: thư mục làm việc,
   - Parameters: tham số dòng lệnh.
3. Đặt breakpoint (`F2`) ở chỗ cần dừng, ví dụ đầu `main`.
4. Nhấn `F9`.

Khi dừng, giao diện chuyển sang chế độ debug với các cửa sổ: **General registers**, **Stack view**,
**Hex view** (bộ nhớ), **Modules**, **Threads**, **Debug output**.

### 18.4. Attach vào tiến trình

**Debugger → Attach to process**: chọn tiến trình đang chạy. Hữu ích với dịch vụ hoặc chương
trình đã được unpack trong bộ nhớ.

### 18.5. Remote debugging

Thư mục `dbgsrv/` trong thư mục cài IDA chứa các debug server:

| File | Nền tảng đích |
|---|---|
| `win64_remote64.exe` (tên tùy phiên bản) | Windows x64 |
| `win32_remote.exe` | Windows x86 (nếu còn được cung cấp) |
| `linux_server64` | Linux x64 |
| `linux_server` | Linux x86 |
| `armlinux_server`, `arm64_linux_server` | Linux ARM |
| `android_server`, `android_server64` | Android |
| `mac_server*` | macOS |

Quy trình:

```bash
# Trên máy đích (ví dụ máy ảo Linux)
./linux_server64 -p23946 -Pmatkhau
# -p: cổng (mặc định 23946), -P: mật khẩu
```

Trên máy chạy IDA:

1. Chọn **Remote Linux debugger**.
2. **Debugger → Process options**: Hostname = IP máy đích, Port = 23946, Password = matkhau,
   Application = đường dẫn file **trên máy đích**.
3. `F9` để chạy.

### 18.6. Breakpoint nâng cao

Chuột phải trên breakpoint → **Edit breakpoint**:

| Tùy chọn | Ý nghĩa |
|---|---|
| Condition | Điều kiện (IDC hoặc Python), ví dụ `GetRegValue("eax") == 5` |
| Hardware | Dùng breakpoint phần cứng (không sửa code – né được kiểm tra checksum) |
| Hardware mode | Execute / Write / Read-Write, kích thước 1/2/4/8 byte |
| Break | Có dừng hay không (bỏ chọn để chỉ log) |
| Trace | Ghi lại khi chạm |
| Refresh debugger memory | Cập nhật bộ nhớ khi dừng |
| Enable tracing / Log | In thông điệp mà không dừng |

Ví dụ điều kiện bằng Python (chọn ngôn ngữ Python ở dropdown của ô Condition):

```python
# Chỉ dừng khi tham số thứ nhất (RCX trên Windows x64) trỏ tới chuỗi chứa "config"
import idc, ida_bytes
s = idc.get_strlit_contents(idc.get_reg_value("rcx"), -1, idc.STRTYPE_C_16)
return s is not None and b"config" in s
```

Hàm điều kiện trả về `True` để dừng, `False` để tiếp tục.

### 18.7. Breakpoint trên API

Đặt breakpoint vào hàm DLL để bắt hành vi:

- Mở **Modules**, double-click `kernel32.dll` hoặc `kernelbase.dll`, tìm `VirtualAlloc`, `F2`.
- Hoặc gõ `G` → `kernel32_VirtualAlloc` / `VirtualAlloc` (tên hiển thị tùy phiên bản và việc nạp symbol).

Các API thường đặt breakpoint khi unpack/phân tích:

| API | Lý do |
|---|---|
| `VirtualAlloc`, `VirtualProtect` | Cấp phát/đổi quyền vùng nhớ để giải nén code |
| `WriteProcessMemory`, `CreateRemoteThread` | Tiêm code vào tiến trình khác |
| `LoadLibraryA/W`, `GetProcAddress` | Nạp API động |
| `CreateProcessW` | Tạo tiến trình con (process hollowing) |
| `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | Kiểm tra debugger |
| `CryptDecrypt`, `BCryptDecrypt` | Giải mã dữ liệu |
| `InternetOpenUrlW`, `WinHttpSendRequest`, `send`, `recv` | Giao tiếp mạng |

### 18.8. Tracing

- **Instruction tracing**: ghi lại mọi lệnh đã thực thi (chậm nhưng chi tiết).
- **Function tracing**: chỉ ghi các lời gọi hàm.
- **Basic block tracing**: ghi các khối đã chạy – kết hợp với tô màu để thấy đường đi thực tế.
- Xem kết quả: **Debugger → Tracing → Trace window**.

### 18.9. Memory snapshot

Khi tiến trình đang dừng sau khi đã unpack trong bộ nhớ, **Debugger → Take memory snapshot**
sẽ chép vùng nhớ vào database. Sau khi dừng debug, bạn vẫn còn code đã giải nén để phân tích tĩnh.

### 18.10. Debug với GDB stub (QEMU, thiết bị nhúng)

```bash
# Chạy firmware ARM trong QEMU, mở GDB stub ở cổng 1234 và dừng chờ
qemu-arm -g 1234 ./firmware_app
# hoặc chế độ hệ thống
qemu-system-arm -M virt -kernel image.bin -s -S
```

Trong IDA: chọn **Remote GDB debugger**, Hostname `127.0.0.1`, Port `1234`, rồi
**Debugger → Attach to process** (hoặc Start process tùy cấu hình). Trong **Debugger options →
Set specific options** chọn đúng kiến trúc.

---

## 19. Ngôn ngữ script IDC

### 19.1. Giới thiệu

IDC là ngôn ngữ script có cú pháp giống C, có sẵn trong IDA từ rất lâu. Ngày nay IDAPython phổ biến
hơn, nhưng IDC vẫn hữu ích cho biểu thức nhanh, điều kiện breakpoint và các script cũ.

### 19.2. Chạy IDC

- Ô lệnh ở cửa sổ Output (chọn **IDC**).
- **File → Script command** (`Shift+F2`): cửa sổ soạn script nhiều dòng.
- **File → Script file** (`Alt+F7`): chạy file `.idc`.

### 19.3. Cú pháp cơ bản

```c
#include <idc.idc>

static main()
{
    auto ea, name, count;

    count = 0;
    ea = get_screen_ea();
    name = get_func_name(ea);
    msg("Con trỏ đang ở %a trong hàm %s\n", ea, name);

    // Duyệt toàn bộ hàm
    for (ea = get_next_func(0); ea != BADADDR; ea = get_next_func(ea)) {
        count++;
    }
    msg("Tổng số hàm: %d\n", count);
}
```

Điểm cần nhớ:

- Biến khai báo bằng `auto`, không có kiểu tĩnh.
- `static` để khai báo hàm.
- `msg()` in ra cửa sổ Output; `%a` in địa chỉ, `%s` chuỗi, `%d` số, `%x` hex.
- `BADADDR` là hằng địa chỉ không hợp lệ.

### 19.4. Một số hàm IDC hữu ích

| Hàm | Công dụng |
|---|---|
| `get_screen_ea()` | Địa chỉ con trỏ |
| `jumpto(ea)` | Nhảy tới địa chỉ |
| `get_func_name(ea)` | Tên hàm chứa `ea` |
| `set_name(ea, "ten", SN_CHECK)` | Đặt tên |
| `set_cmt(ea, "comment", 0/1)` | Đặt comment (1 = repeatable) |
| `byte(ea)`, `word(ea)`, `dword(ea)`, `qword(ea)` | Đọc giá trị |
| `patch_byte(ea, val)` | Patch byte |
| `print_insn_mnem(ea)` | Mnemonic của lệnh |
| `print_operand(ea, n)` | Operand thứ n |
| `next_head(ea, maxea)` | Mục kế tiếp |
| `get_first_cref_to(ea)` / `get_next_cref_to(ea, cur)` | Duyệt code xref |
| `get_first_dref_to(ea)` / `get_next_dref_to(ea, cur)` | Duyệt data xref |
| `find_binary(ea, flag, "55 8B EC")` | Tìm byte (bản cũ; bản mới khuyến khích API khác) |
| `ask_str(default, 0, "prompt")` | Hỏi người dùng nhập chuỗi |

### 19.5. Ví dụ: giải mã XOR một vùng

```c
#include <idc.idc>

static main()
{
    auto start, size, key, i, b;

    start = 0x405000;
    size  = 0x40;
    key   = 0x5A;

    for (i = 0; i < size; i++) {
        b = byte(start + i);
        patch_byte(start + i, b ^ key);
    }
    create_strlit(start, start + size);
    msg("Đã giải mã %d byte tại %a\n", size, start);
}
```

---

## 20. IDAPython

IDAPython là cách chính để tự động hóa IDA. Từ IDA 7.4, API dùng Python 3 và tên hàm theo chuẩn
mới (snake_case như `get_func_name`). Các tên cũ (`GetFunctionName`) đã bị loại bỏ.

### 20.1. Các module quan trọng

| Module | Nội dung |
|---|---|
| `idc` | Hàm tương thích IDC, tiện dụng cho thao tác nhanh |
| `idautils` | Hàm tiện ích sinh danh sách: `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |
| `idaapi` | Module tổng hợp (import lại nhiều module `ida_*`) |
| `ida_funcs` | Hàm: `get_func`, `add_func`, `func_t` |
| `ida_bytes` | Byte và cờ: `get_byte`, `patch_byte`, `create_strlit`, `get_flags` |
| `ida_name` | Tên: `set_name`, `get_name`, `demangle_name` |
| `ida_xref` | Xref: `add_cref`, `add_dref`, `xrefblk_t` |
| `ida_segment` | Segment: `getseg`, `get_segm_name` |
| `ida_ua` | Decode lệnh: `insn_t`, `decode_insn` |
| `ida_hexrays` | Decompiler: `decompile`, ctree visitor |
| `ida_kernwin` | Giao diện: `ask_str`, `jumpto`, `msg`, action, chooser |
| `ida_typeinf` | Kiểu dữ liệu: `tinfo_t`, `parse_decl`, `apply_tinfo` |
| `ida_nalt` | Thông tin phụ: import, đường dẫn file gốc, string type |
| `ida_auto` | Auto-analysis: `auto_wait`, `plan_and_wait` |
| `ida_dbg` | Debugger |
| `ida_gdl` | Flow chart, basic block |
| `ida_entry` | Entry point và export |
| `ida_search` | Tìm kiếm (một số hàm đã được thay thế trong IDA 9) |
| `ida_idaapi` | Hằng số như `BADADDR`, lớp `plugin_t` |

### 20.2. Chạy script

- Ô lệnh Output (chọn **Python**).
- `Shift+F2`: Script command, chọn ngôn ngữ Python, viết nhiều dòng, nhấn **Run**.
- `Alt+F7`: chạy file `.py`.
- **File → Recent scripts** (`Alt+F9`): chạy lại script gần đây.
- Tự động khi khởi động: `idapythonrc.py` trong IDAUSR.

### 20.3. Các thao tác cơ bản

```python
import idc
import idautils
import idaapi
import ida_funcs
import ida_bytes
import ida_name

ea = idc.get_screen_ea()                 # địa chỉ con trỏ
print(hex(ea))

print(idc.get_func_name(ea))             # tên hàm chứa ea
print(idc.print_insn_mnem(ea))           # mnemonic, ví dụ 'mov'
print(idc.print_operand(ea, 0))          # operand đầu tiên
print(idc.print_operand(ea, 1))          # operand thứ hai
print(idc.get_operand_value(ea, 1))      # giá trị số của operand
print(idc.GetDisasm(ea))                 # cả dòng disassembly

print(hex(ida_bytes.get_byte(ea)))       # đọc 1 byte
print(hex(ida_bytes.get_dword(ea)))      # đọc 4 byte
print(ida_bytes.get_bytes(ea, 16))       # đọc 16 byte dạng bytes

ida_name.set_name(ea, "my_label", ida_name.SN_NOWARN)   # đặt tên
idc.set_cmt(ea, "Comment thường", 0)                    # comment thường
idc.set_cmt(ea, "Comment lặp lại", 1)                   # comment repeatable
idc.set_func_cmt(ea, "Comment cho cả hàm", 1)

idc.jumpto(0x401000)                     # nhảy tới địa chỉ
print(hex(idaapi.get_imagebase()))       # image base
print(idc.get_input_file_path())         # đường dẫn file gốc
```

### 20.4. Duyệt segment, hàm và lệnh

```python
import idc, idautils, ida_funcs

# Liệt kê segment
for seg_ea in idautils.Segments():
    print("%-10s %08X - %08X" % (idc.get_segm_name(seg_ea),
                                 idc.get_segm_start(seg_ea),
                                 idc.get_segm_end(seg_ea)))

# Liệt kê hàm và kích thước
for func_ea in idautils.Functions():
    f = ida_funcs.get_func(func_ea)
    name = idc.get_func_name(func_ea)
    print("%08X  %-40s  %6d bytes" % (func_ea, name, f.end_ea - f.start_ea))

# Duyệt mọi lệnh trong một hàm
func_ea = idc.get_name_ea_simple("main")
for insn_ea in idautils.FuncItems(func_ea):
    print("%08X: %s" % (insn_ea, idc.GetDisasm(insn_ea)))

# Duyệt mọi "head" (lệnh hoặc dữ liệu) trong một segment
import ida_segment
seg = ida_segment.get_segm_by_name(".text")
for head in idautils.Heads(seg.start_ea, seg.end_ea):
    if idc.is_code(idc.get_full_flags(head)):
        pass  # xử lý lệnh
```

### 20.5. Làm việc với xref

```python
import idc, idautils, ida_xref

target = idc.get_name_ea_simple("VirtualAlloc")
# Với hàm import, tên có thể là "VirtualAlloc" hoặc "__imp_VirtualAlloc" tùy loader

for xref in idautils.XrefsTo(target):
    print("Từ %08X (%s) kiểu %s" % (
        xref.frm,
        idc.get_func_name(xref.frm),
        idautils.XrefTypeName(xref.type)))

# Xref từ một địa chỉ đi ra
for xref in idautils.XrefsFrom(idc.get_screen_ea()):
    print(hex(xref.to), idautils.XrefTypeName(xref.type))

# Chỉ code xref tới (người gọi)
callers = set()
for ea in idautils.CodeRefsTo(target, 0):
    callers.add(idc.get_func_name(ea))
print(sorted(callers))
```

### 20.6. Liệt kê import và chuỗi

```python
import ida_nalt, idautils

# Import
def list_imports():
    for i in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(i)
        print("=== %s ===" % module)

        def callback(ea, name, ordinal):
            print("  %08X  %s (ord %d)" % (ea, name if name else "", ordinal))
            return True   # trả về True để tiếp tục duyệt

        ida_nalt.enum_import_names(i, callback)

list_imports()

# Chuỗi
for s in idautils.Strings():
    print("%08X  len=%3d  %s" % (s.ea, s.length, str(s)))
```

Có thể cấu hình loại chuỗi được quét:

```python
sc = idautils.Strings(default_setup=False)
sc.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16], minlen=5)
for s in sc:
    print(hex(s.ea), str(s))
```

### 20.7. Ví dụ thực tế 1: Tô màu mọi lệnh call

```python
import idc, idautils

COLOR_CALL = 0xCCFFFF   # định dạng BGR: vàng nhạt

for func_ea in idautils.Functions():
    for ea in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(ea) == "call":
            idc.set_color(ea, idc.CIC_ITEM, COLOR_CALL)
print("Xong.")
```

### 20.8. Ví dụ thực tế 2: Giải mã chuỗi bị mã hóa

Giả sử malware có hàm `decrypt_str(char *enc, int len)` dùng XOR với key `0x37`, và mỗi lời gọi
có dạng:

```asm
push    0Ch                 ; len
push    offset unk_40A120   ; enc
call    decrypt_str
```

Script tự động tìm mọi lời gọi, giải mã, và đặt comment:

```python
import idc, idautils, ida_bytes

DECRYPT_FUNC = idc.get_name_ea_simple("decrypt_str")
KEY = 0x37

def find_push_args(call_ea, count):
    """Đi ngược từ lệnh call, lấy giá trị của `count` lệnh push gần nhất."""
    args = []
    ea = call_ea
    while len(args) < count:
        ea = idc.prev_head(ea)
        if ea == idc.BADADDR:
            break
        if idc.print_insn_mnem(ea) == "push":
            args.append(idc.get_operand_value(ea, 0))
    return args   # args[0] = tham số 1 (push gần call nhất)

def decrypt(data):
    return bytes(b ^ KEY for b in data)

count = 0
for call_ea in idautils.CodeRefsTo(DECRYPT_FUNC, 0):
    args = find_push_args(call_ea, 2)
    if len(args) < 2:
        print("Không lấy được tham số tại %08X" % call_ea)
        continue
    enc_ea, length = args[0], args[1]
    plain = decrypt(ida_bytes.get_bytes(enc_ea, length))
    text = plain.decode("latin-1")
    idc.set_cmt(call_ea, 'Giải mã: "%s"' % text, 0)
    idc.set_cmt(enc_ea, text, 1)
    count += 1
    print("%08X -> %s" % (call_ea, text))

print("Đã giải mã %d chuỗi" % count)
```

> Đây là cách đơn giản dựa trên mẫu `push`. Với x64 (tham số qua thanh ghi) hoặc code phức tạp,
> nên dùng decompiler (ctree) hoặc giả lập (ví dụ thư viện Unicorn/flare-emu) để lấy giá trị tham số
> chính xác hơn.

### 20.9. Ví dụ thực tế 3: Đổi tên hàng loạt theo chuỗi log

Nhiều chương trình gọi hàm log với tên hàm làm tham số:
`log_error("parse_config", "invalid key")`. Có thể dùng chuỗi này để đặt tên hàm:

```python
import idc, idautils, ida_bytes, ida_name

LOG_FUNC = idc.get_name_ea_simple("log_error")

for call_ea in idautils.CodeRefsTo(LOG_FUNC, 0):
    func = idc.get_func_attr(call_ea, idc.FUNCATTR_START)
    if func == idc.BADADDR:
        continue
    if not idc.get_func_name(func).startswith("sub_"):
        continue    # bỏ qua hàm đã có tên
    # Tìm lệnh nạp chuỗi gần nhất phía trước call (x86: push offset ...)
    ea = call_ea
    for _ in range(10):
        ea = idc.prev_head(ea)
        if idc.print_insn_mnem(ea) == "push" and idc.get_operand_type(ea, 0) == idc.o_imm:
            s = idc.get_strlit_contents(idc.get_operand_value(ea, 0), -1, idc.STRTYPE_C)
            if s and s.isascii() and b" " not in s:
                new_name = "fn_" + s.decode()
                if ida_name.set_name(func, new_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
                    print("%08X -> %s" % (func, new_name))
            break
```

### 20.10. Làm việc với decompiler qua Python

```python
import ida_hexrays, idc

if not ida_hexrays.init_hexrays_plugin():
    print("Decompiler không khả dụng")
else:
    ea = idc.get_screen_ea()
    cfunc = ida_hexrays.decompile(ea)
    print(cfunc)                 # in toàn bộ pseudocode

    # Liệt kê biến cục bộ
    for lv in cfunc.get_lvars():
        print(lv.name, lv.type(), "arg" if lv.is_arg_var else "local")
```

Duyệt cây ctree để tìm mọi lời gọi hàm trong pseudocode:

```python
import ida_hexrays, idc

class CallFinder(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.calls = []

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            callee = e.x
            if callee.op == ida_hexrays.cot_obj:
                self.calls.append((e.ea, idc.get_name(callee.obj_ea), e.a.size()))
        return 0   # 0 = tiếp tục duyệt

cfunc = ida_hexrays.decompile(idc.get_screen_ea())
v = CallFinder()
v.apply_to(cfunc.body, None)
for ea, name, nargs in v.calls:
    print("%08X  %s  (%d tham số)" % (ea, name, nargs))
```

Decompile toàn bộ chương trình ra file:

```python
import ida_hexrays, idautils, idc

out = open("all_functions.c", "w", encoding="utf-8")
for ea in idautils.Functions():
    try:
        cfunc = ida_hexrays.decompile(ea)
        out.write("// %s @ %08X\n%s\n\n" % (idc.get_func_name(ea), ea, cfunc))
    except ida_hexrays.DecompilationFailure as e:
        out.write("// Không decompile được %08X: %s\n\n" % (ea, e))
out.close()
```

### 20.11. Làm việc với kiểu dữ liệu

```python
import ida_typeinf, idc

# Khai báo struct mới vào Local Types
decl = """
struct config_t {
    char server[64];
    unsigned short port;
    unsigned int sleep_ms;
    unsigned char key[16];
};
"""
errors = ida_typeinf.idc_parse_types(decl, 0)
print("Số lỗi:", errors)

# Áp dụng kiểu cho một địa chỉ dữ liệu
ea = 0x40B000
idc.SetType(ea, "struct config_t")     # hoặc idc.apply_type(...)

# Đặt prototype cho hàm
func = idc.get_name_ea_simple("decrypt_str")
idc.SetType(func, "char *__cdecl decrypt_str(char *enc, int len);")
```

### 20.12. Tương tác người dùng

```python
import ida_kernwin

name = ida_kernwin.ask_str("default", 0, "Nhập tên hàm:")
addr = ida_kernwin.ask_addr(0x401000, "Nhập địa chỉ:")
yes = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "Tiếp tục?")
ida_kernwin.info("Thông báo cho người dùng")
ida_kernwin.warning("Cảnh báo!")
path = ida_kernwin.ask_file(0, "*.txt", "Chọn file để lưu")
```

### 20.13. Tạo cửa sổ danh sách (Chooser)

```python
import ida_kernwin, idautils, idc

class BigFuncChooser(ida_kernwin.Choose):
    def __init__(self, items):
        super().__init__("Hàm lớn",
                         [["Địa chỉ", 12 | ida_kernwin.Choose.CHCOL_HEX],
                          ["Tên", 30],
                          ["Kích thước", 10 | ida_kernwin.Choose.CHCOL_DEC]])
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        ea, name, size = self.items[n]
        return ["%08X" % ea, name, str(size)]

    def OnSelectLine(self, n):
        idc.jumpto(self.items[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

items = []
for ea in idautils.Functions():
    size = idc.get_func_attr(ea, idc.FUNCATTR_END) - ea
    if size > 500:
        items.append((ea, idc.get_func_name(ea), size))
items.sort(key=lambda x: -x[2])
BigFuncChooser(items).Show()
```

### 20.14. Đăng ký action và phím tắt

```python
import ida_kernwin, idc, idaapi

class CopyAddrHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        ea = idc.get_screen_ea()
        print("Địa chỉ: 0x%X  RVA: 0x%X" % (ea, ea - idaapi.get_imagebase()))
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

action = ida_kernwin.action_desc_t(
    "myscripts:print_rva",        # tên nội bộ, phải duy nhất
    "In địa chỉ và RVA",          # nhãn
    CopyAddrHandler(),
    "Ctrl+Shift+A",               # phím tắt
    "In địa chỉ hiện tại và RVA", # tooltip
    -1)
ida_kernwin.register_action(action)
ida_kernwin.attach_action_to_menu("Edit/", "myscripts:print_rva", ida_kernwin.SETMENU_APP)
```

### 20.15. Hook sự kiện

```python
import ida_idp

class RenameLogger(ida_idp.IDB_Hooks):
    def renamed(self, ea, new_name, local_name, old_name):
        print("Đổi tên %08X: %s -> %s" % (ea, old_name, new_name))
        return 0

hooks = RenameLogger()
hooks.hook()
# hooks.unhook() để gỡ
```

Các lớp hook khác: `ida_kernwin.UI_Hooks` (sự kiện giao diện), `ida_dbg.DBG_Hooks` (sự kiện
debugger), `ida_hexrays.Hexrays_Hooks` (sự kiện decompiler).

### 20.16. Script debugger

```python
import ida_dbg, idc

class MyDbgHook(ida_dbg.DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        print("Chạm breakpoint tại %08X, RAX=%X" % (ea, idc.get_reg_value("rax")))
        return 0      # 0 = dừng như bình thường
    def dbg_process_exit(self, pid, tid, ea, code):
        print("Tiến trình thoát với mã", code)

hook = MyDbgHook()
hook.hook()

ida_dbg.add_bpt(idc.get_name_ea_simple("main"))
ida_dbg.start_process()
```

### 20.17. Mẹo viết IDAPython

- Gọi `ida_auto.auto_wait()` ở đầu script batch để chờ phân tích xong.
- Dùng `idc.BADADDR` để kiểm tra lỗi trả về.
- Hàm `idautils.*` trả về generator – bọc trong `list()` nếu cần dùng nhiều lần.
- Thay đổi database trong vòng lặp lớn có thể chậm; cân nhắc tắt cập nhật giao diện hoặc chạy batch.
- Đọc tài liệu API: `https://python.docs.hex-rays.com` (hoặc trang tài liệu tương ứng phiên bản).
- Gõ `help(idc.get_func_name)` trong ô lệnh để xem docstring.
- Nhiều hàm tìm kiếm cũ (`idc.find_binary`) đã bị thay thế trong IDA 9 – kiểm tra hướng dẫn
  chuyển đổi (porting guide) khi script cũ báo lỗi.

---

## 21. Viết và cài đặt Plugin

### 21.1. Cài đặt plugin có sẵn

1. Tải plugin (thường là file `.py` hoặc thư mục, hoặc file `.dll/.so/.dylib` đã biên dịch).
2. Sao chép vào `IDAUSR/plugins/` (khuyến nghị) hoặc `<thư mục cài IDA>/plugins/`.
3. Cài các thư viện Python plugin yêu cầu (bằng đúng interpreter IDA dùng).
4. Khởi động lại IDA, kiểm tra trong **Edit → Plugins**.

Các bản IDA gần đây còn hỗ trợ quản lý plugin qua **Hex-Rays Plugin Repository / hcli**
(tùy phiên bản) – xem tài liệu chính thức.

### 21.2. Plugin phổ biến

| Plugin | Công dụng |
|---|---|
| **HexRaysPyTools** | Tái tạo struct, quản lý vtable, cải thiện pseudocode |
| **Diaphora** | So sánh hai database (patch diffing), mã nguồn mở |
| **BinDiff** | So sánh binary (Google, miễn phí) |
| **findcrypt-yara** | Phát hiện hằng số mã hóa |
| **capa explorer** (FLARE) | Nhận diện khả năng (capabilities) của chương trình theo luật |
| **FLARE IDA scripts** | Bộ script của Mandiant FLARE (shellcode hashes, stack strings...) |
| **Keypatch** | Assemble/patch nhiều kiến trúc dùng Keystone |
| **LazyIDA** | Tiện ích: copy byte, chuyển đổi dữ liệu, ... |
| **ret-sync** | Đồng bộ IDA với debugger ngoài (WinDbg, x64dbg, GDB) |
| **ClassInformer** | Khôi phục lớp C++ từ RTTI MSVC |
| **HRDevHelper** | Hiển thị cây ctree – hỗ trợ viết plugin decompiler |
| **Lighthouse** | Hiển thị code coverage trên IDA |
| **IDA Signsrch** | Nhận diện thuật toán theo chữ ký |
| **Gepetto** / các plugin AI | Dùng mô hình ngôn ngữ để giải thích/đặt tên hàm (cẩn trọng về dữ liệu gửi đi) |

> Kiểm tra tính tương thích phiên bản: nhiều plugin cũ chưa cập nhật cho API IDA 9.

### 21.3. Cấu trúc plugin Python tối thiểu

```python
# file: IDAUSR/plugins/hello_plugin.py
import ida_idaapi
import ida_kernwin

class HelloPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        ida_kernwin.info("Xin chào từ plugin!")
        return True

    def term(self):
        pass

class HelloPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI          # API mới, hỗ trợ nhiều database
    comment = "Plugin ví dụ"
    help = "Hiển thị lời chào"
    wanted_name = "Hello Plugin"
    wanted_hotkey = "Ctrl+Alt+H"

    def init(self):
        return HelloPlugmod()

def PLUGIN_ENTRY():
    return HelloPlugin()
```

Giải thích:

| Thành phần | Ý nghĩa |
|---|---|
| `PLUGIN_ENTRY()` | Hàm IDA gọi để lấy đối tượng plugin |
| `flags` | `PLUGIN_MULTI` (khuyến nghị), `PLUGIN_KEEP`, `PLUGIN_HIDE`, `PLUGIN_FIX`, `PLUGIN_PROC`... |
| `init()` | Gọi khi nạp; trả về `plugmod_t` (với PLUGIN_MULTI), hoặc `PLUGIN_OK`/`PLUGIN_KEEP`/`PLUGIN_SKIP` (kiểu cũ) |
| `run(arg)` | Gọi khi người dùng kích hoạt plugin |
| `term()` | Gọi khi gỡ plugin |
| `wanted_name` | Tên trong menu Edit → Plugins |
| `wanted_hotkey` | Phím tắt |

### 21.4. Plugin kiểu cũ (vẫn được hỗ trợ)

```python
import idaapi

class OldStylePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL     # gỡ sau khi chạy xong
    comment = "Plugin kiểu cũ"
    help = ""
    wanted_name = "Old Style"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("Đang chạy plugin kiểu cũ")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return OldStylePlugin()
```

### 21.5. Plugin C++ với IDA SDK

IDA SDK (đi kèm bản có bản quyền, các bản mới công bố rộng rãi hơn) cho phép viết plugin, loader,
processor module bằng C++ với hiệu năng cao.

```cpp
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>

struct plugin_ctx_t : public plugmod_t
{
  bool idaapi run(size_t) override
  {
    size_t n = get_func_qty();
    msg("Database có %u hàm\n", (unsigned)n);
    return true;
  }
};

static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,          // flags
  init,                  // init
  nullptr,               // term
  nullptr,               // run (dùng plugmod_t::run)
  "Đếm hàm",             // comment
  "Đếm số hàm trong database", // help
  "Function Counter",    // wanted_name
  "Ctrl+Alt+C"           // wanted_hotkey
};
```

Biên dịch theo hướng dẫn trong SDK (CMake hoặc makefile có sẵn), sinh `.dll` (Windows),
`.so` (Linux), `.dylib` (macOS), rồi đặt vào thư mục `plugins`.

### 21.6. Loader và processor module

- **Loader**: dạy IDA đọc định dạng file mới (ví dụ firmware riêng của một hãng). Loader Python
  cần hai hàm `accept_file(li, filename)` và `load_file(li, neflags, format)`.
- **Processor module**: dạy IDA disassemble một kiến trúc CPU mới (ví dụ máy ảo tùy chỉnh trong
  một bài CTF). Có thể viết bằng Python, kế thừa `processor_t`.

Ví dụ khung loader Python:

```python
# file: IDAUSR/loaders/myfw_loader.py
import ida_idp, ida_segment, ida_bytes, ida_entry, idc

MAGIC = b"MYFW"

def accept_file(li, filename):
    li.seek(0)
    if li.read(4) == MAGIC:
        return {"format": "MyFirmware v1", "processor": "arm"}
    return 0

def load_file(li, neflags, format):
    ida_idp.set_processor_type("arm", ida_idp.SETPROC_LOADER)
    li.seek(4)
    load_addr = int.from_bytes(li.read(4), "little")
    entry     = int.from_bytes(li.read(4), "little")
    size      = int.from_bytes(li.read(4), "little")

    seg = ida_segment.segment_t()
    seg.start_ea = load_addr
    seg.end_ea   = load_addr + size
    seg.bitness  = 1          # 1 = 32-bit
    ida_segment.add_segm_ex(seg, "CODE", "CODE", 0)

    li.file2base(16, load_addr, load_addr + size, 0)
    ida_entry.add_entry(entry, entry, "start", 1)
    return 1
```

---

## 22. Chế độ dòng lệnh, batch và idalib

### 22.1. Tham số dòng lệnh phổ biến

| Tham số | Ý nghĩa |
|---|---|
| `-A` | Chế độ tự động (autonomous) – không hiện hộp thoại |
| `-B` | Batch mode: phân tích, tạo `.asm` và database rồi thoát |
| `-c` | Xóa database cũ, tạo mới |
| `-S"script.py arg1 arg2"` | Chạy script sau khi mở database |
| `-L"log.txt"` | Ghi log ra file |
| `-o<đường dẫn>` | Đường dẫn database đầu ra |
| `-p<cpu>` | Chọn processor, ví dụ `-parm`, `-pmetapc` |
| `-T<loại>` | Chọn loader/định dạng file |
| `-b<địa chỉ>` | Địa chỉ nạp (đơn vị paragraph 16 byte với một số loader) |
| `-P+` / `-P-` | Pack / không pack database khi đóng |
| `-R` | Nạp resource (PE) |
| `-t` | Tạo database rỗng |
| `-Oplugin:options` | Truyền tùy chọn cho plugin |

Các bản cũ có `idat`/`idat64` (giao diện text) dùng cho batch; IDA 9 có `idat` (text) và `ida`
(GUI) đã hợp nhất 32/64-bit.

### 22.2. Ví dụ phân tích hàng loạt

Script `export_funcs.py`:

```python
import idc, idautils, ida_auto, ida_nalt, os

ida_auto.auto_wait()     # chờ phân tích xong

out_dir = idc.ARGV[1] if len(idc.ARGV) > 1 else "."
name = os.path.basename(ida_nalt.get_input_file_path())
with open(os.path.join(out_dir, name + "_funcs.txt"), "w") as f:
    for ea in idautils.Functions():
        f.write("%08X %s\n" % (ea, idc.get_func_name(ea)))

idc.qexit(0)              # thoát IDA, rất quan trọng trong batch mode
```

Chạy hàng loạt trên Linux:

```bash
#!/bin/bash
IDA=~/idapro-9.x/idat
mkdir -p results
for f in samples/*; do
    echo "Đang xử lý $f"
    "$IDA" -A -c -L"results/$(basename "$f").log" \
           -S"export_funcs.py results" "$f"
done
```

Trên Windows (PowerShell):

```powershell
$ida = "C:\Program Files\IDA Professional 9.x\idat.exe"
Get-ChildItem .\samples | ForEach-Object {
    & $ida -A -c "-Lresults\$($_.Name).log" "-Sexport_funcs.py results" $_.FullName
}
```

### 22.3. idalib (IDA 9+)

**idalib** cho phép dùng IDA như một thư viện Python/C++ trong chương trình của bạn, không cần mở
giao diện:

```bash
# Thiết lập (chạy script đi kèm trong thư mục cài đặt IDA, tên có thể khác theo phiên bản)
python <IDA_DIR>/idalib/python/py-activate-idalib.py
pip install <IDA_DIR>/idalib/python
```

```python
import idapro            # phải import đầu tiên

idapro.open_database("sample.exe", run_auto_analysis=True)

import idautils, idc
for ea in idautils.Functions():
    print(hex(ea), idc.get_func_name(ea))

idapro.close_database(save=False)
```

Ứng dụng: tích hợp IDA vào pipeline phân tích mã độc, CI kiểm tra binary, công cụ so sánh phiên
bản tự động.

### 22.4. Tạo file đầu ra

**File → Produce file**:

| Loại | Phím | Nội dung |
|---|---|---|
| Create ASM file | `Alt+F10` | Listing assembly |
| Create LST file | | Listing kèm địa chỉ và byte |
| Create MAP file | | Bảng tên/địa chỉ (dùng cho debugger khác) |
| Create C file | `Ctrl+F5` | Pseudocode toàn chương trình |
| Create HTML file | | Listing dạng HTML |
| Create DIF file | | Danh sách byte đã patch |
| Create C header file | | Khai báo kiểu từ Local Types |
| Dump database to IDC file | | Script IDC tái tạo tên/comment/kiểu – hữu ích để chuyển thông tin giữa các database |

---

## 23. Phân tích các kiến trúc khác

### 23.1. ARM 32-bit

- Hai chế độ lệnh: ARM (4 byte) và Thumb (2/4 byte). Địa chỉ lẻ trong con trỏ hàm thường nghĩa
  là hàm Thumb (bit 0 = 1).
- Dùng `Alt+G` đặt thanh ghi ảo `T` (xem 9.7).
- `LR` (R14) chứa địa chỉ trả về; `BL` gọi hàm; `BX LR` trả về.
- Hằng số lớn thường được nạp từ **literal pool** ngay sau hàm: `LDR R0, =0x12345678`.

```asm
PUSH    {R4-R7,LR}
LDR     R0, =aHello         ; "Hello"
BL      puts
MOVS    R0, #0
POP     {R4-R7,PC}
```

### 23.2. ARM64 (AArch64)

- Lệnh cố định 4 byte. Tham số X0–X7, trả về X0, `X30` là LR.
- Địa chỉ thường tạo bằng cặp `ADRP` + `ADD`/`LDR` – IDA tự gộp và hiển thị tên.
- Gặp nhiều ở Android (`.so`), iOS, macOS Apple Silicon.
- Lưu ý PAC (Pointer Authentication) trên Apple: lệnh `PACIASP`, `RETAA`, `BLRAA`...

### 23.3. MIPS

- Có **delay slot**: lệnh ngay sau lệnh nhảy/gọi luôn được thực thi trước khi nhảy. IDA hiển thị
  delay slot thụt lề hoặc ghi chú.
- Thanh ghi `$a0–$a3` là tham số, `$v0` trả về, `$ra` địa chỉ trả về, `$gp` dùng để truy cập dữ
  liệu toàn cục. Đảm bảo IDA xác định đúng giá trị `$gp` (Processor options) để xref đúng.
- Phổ biến trong router, thiết bị mạng. Chú ý endian (MIPS big-endian `mipsb` hoặc little-endian `mipsl`).

### 23.4. Firmware thô (raw binary)

Quy trình:

1. Mở file, chọn **Binary file** loader.
2. Chọn đúng **Processor type** (ví dụ `ARM Little-endian [ARM]`).
3. Xác định **địa chỉ nạp** (loading address). Gợi ý:
   - Đọc datasheet của vi điều khiển (ví dụ STM32 flash bắt đầu `0x08000000`).
   - Bảng vector ngắt Cortex-M ở đầu file: word đầu là stack pointer ban đầu, word thứ hai là
     địa chỉ reset handler (lẻ = Thumb) – suy ra base address.
   - So khớp địa chỉ tuyệt đối của con trỏ chuỗi với vị trí chuỗi trong file.
4. Tạo thêm segment cho RAM và vùng thanh ghi ngoại vi (**Edit → Segments → Create segment**)
   để IDA hiểu các truy cập bộ nhớ.
5. Áp dụng file SVD (mô tả thanh ghi ngoại vi) bằng plugin như SVD loader để đặt tên thanh ghi.

### 23.5. .NET, Java, Python bytecode

- IDA có thể mở file .NET, nhưng công cụ chuyên dụng như **dnSpyEx** hoặc **ILSpy** cho kết quả
  tốt hơn nhiều.
- Với Java/Android DEX, dùng **JADX**; IDA hữu ích cho phần native (`.so`) của ứng dụng Android.
- Với Python đóng gói (PyInstaller), giải nén rồi dùng công cụ decompile bytecode.

### 23.6. Go và Rust

- Binary Go: liên kết tĩnh, rất lớn, có calling convention riêng (từ Go 1.17 dùng thanh ghi).
  IDA các bản mới khôi phục tên hàm từ metadata `pclntab` khá tốt; cần chú ý chuỗi Go không kết
  thúc bằng `\0` (lưu dạng con trỏ + độ dài).
- Binary Rust: nhiều code generic, tên bị mangle. Bật demangle, tập trung vào hàm trong namespace
  của crate chính, bỏ qua `core::`, `alloc::`, `std::`.

---

## 24. Quy trình phân tích thực tế (walkthrough)

Phần này đi qua một ví dụ hoàn chỉnh: một chương trình crackme tự viết, biên dịch bằng GCC trên
Linux x64 và đã strip symbol. Bạn có thể tự biên dịch để làm theo.

### 24.1. Mã nguồn (để tự biên dịch và thực hành)

```c
// crackme.c  –  gcc -O1 -s -o crackme crackme.c
#include <stdio.h>
#include <string.h>

static const unsigned char enc_flag[] = {
    0x2c, 0x21, 0x24, 0x1a, 0x29, 0x24, 0x1a, 0x26, 0x2a, 0x2b, 0x22, 0x1a, 0x26, 0x30, 0x64, 0x00
};

static int check(const char *s)
{
    size_t n = strlen(s);
    if (n != 15)
        return 0;
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)(s[i] ^ 0x45) != enc_flag[i])
            return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    char buf[64];
    printf("Nhap mat khau: ");
    if (!fgets(buf, sizeof(buf), stdin))
        return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (check(buf))
        puts("Chinh xac!");
    else
        puts("Sai roi.");
    return 0;
}
```

> Hãy giả vờ bạn không có mã nguồn – chỉ có file `crackme` đã strip.

### 24.2. Bước 1 – Thu thập thông tin ban đầu

Trước khi mở IDA, dùng công cụ dòng lệnh:

```bash
file crackme          # ELF 64-bit LSB pie executable, x86-64, stripped
strings -n 5 crackme  # thấy "Nhap mat khau: ", "Chinh xac!", "Sai roi."
```

### 24.3. Bước 2 – Mở trong IDA

1. Kéo thả `crackme` vào IDA, loader `ELF64 for x86-64` được chọn tự động, nhấn **OK**.
2. Chờ `AU: idle`.
3. Vì là file PIE, IDA nạp tại base mặc định (thường `0x0` hoặc theo cấu hình). Các địa chỉ dưới
   đây chỉ mang tính minh họa.

### 24.4. Bước 3 – Tìm main

Cách 1: **Shift+F12** → double-click chuỗi `"Chinh xac!"` → nhấn `X` → nhảy tới hàm sử dụng.

Cách 2: `Ctrl+E` → `start` → thấy:

```asm
start:
    xor     ebp, ebp
    mov     r9, rdx
    pop     rsi
    mov     rdx, rsp
    and     rsp, 0FFFFFFFFFFFFFFF0h
    ...
    lea     rdi, sub_1189          ; tham số 1 của __libc_start_main = main
    call    cs:__libc_start_main_ptr
```

Đặt con trỏ trên `sub_1189`, nhấn `N`, đổi tên thành `main`.

### 24.5. Bước 4 – Decompile main

Nhấn `F5`:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[72]; // [rsp+0h] [rbp-48h] BYREF

  printf("Nhap mat khau: ");
  if ( !fgets(s, 64, stdin) )
    return 1LL;
  s[strcspn(s, "\n")] = 0;
  if ( (unsigned int)sub_1150(s) )
    puts("Chinh xac!");
  else
    puts("Sai roi.");
  return 0LL;
}
```

Nhận xét: `sub_1150` là hàm kiểm tra. Đổi tên thành `check_password` (`N`) và đặt prototype
`int __fastcall check_password(const char *s);` (`Y`).

> Với `-O1`, compiler có thể inline hàm `check` vào `main`. Nếu không thấy lời gọi riêng, phần
> kiểm tra nằm ngay trong `main` – các bước phân tích vẫn tương tự.

### 24.6. Bước 5 – Phân tích hàm kiểm tra

`Enter` vào `check_password`, `F5`:

```c
__int64 __fastcall check_password(const char *a1)
{
  size_t v1; // rax
  __int64 i; // rdx

  v1 = strlen(a1);
  if ( v1 != 15 )
    return 0LL;
  for ( i = 0LL; i != 15; ++i )
  {
    if ( (a1[i] ^ 0x45) != byte_2010[i] )
      return 0LL;
  }
  return 1LL;
}
```

Rút ra:

- Mật khẩu dài 15 ký tự.
- Mỗi ký tự XOR với `0x45` phải bằng `byte_2010[i]`.

Double-click `byte_2010`, nhấn `*` tạo mảng 16 phần tử, `N` đổi tên thành `enc_flag`.

### 24.7. Bước 6 – Giải bằng IDAPython

```python
import idc, ida_bytes
ea = idc.get_name_ea_simple("enc_flag")
data = ida_bytes.get_bytes(ea, 15)
print(bytes(b ^ 0x45 for b in data).decode())
```

Kết quả in ra là mật khẩu `ida_la_cong_cu!`. Kiểm tra lại:

```bash
./crackme
Nhap mat khau: ida_la_cong_cu!
Chinh xac!
```

### 24.8. Bước 7 – Kiểm chứng bằng debugger (tùy chọn)

1. Chọn **Local Linux debugger** (hoặc **Remote Linux debugger** nếu IDA chạy trên Windows).
2. Đặt breakpoint tại lệnh so sánh trong vòng lặp (`F2`).
3. `F9`, nhập chuỗi thử `AAAAAAAAAAAAAAA`.
4. Khi dừng, xem thanh ghi chứa ký tự đã XOR và byte cần so sánh – xác nhận phân tích tĩnh là đúng.

### 24.9. Quy trình tổng quát cho một binary bất kỳ

```
1. Thu thập thông tin
   ├── file, hash (SHA-256), kích thước, định dạng, kiến trúc
   ├── strings, imports, exports, section, entropy (phát hiện pack)
   └── chạy thử trong sandbox/VM nếu an toàn và được phép

2. Nạp vào IDA
   ├── chọn đúng loader/processor
   ├── nạp symbol (PDB/DWARF) nếu có
   └── chờ auto-analysis xong, áp dụng FLIRT/type library phù hợp

3. Định hướng
   ├── tìm main / DllMain / hàm export / handler chính
   ├── dùng strings và imports làm "mỏ neo"
   └── vẽ sơ đồ các hàm quan trọng (proximity browser, xref graph)

4. Phân tích sâu từng hàm
   ├── decompile, đặt tên, đặt kiểu, định nghĩa struct
   ├── comment kết luận, bookmark các điểm quan trọng
   └── lặp lại: tri thức mới làm rõ thêm các hàm khác

5. Xác minh
   ├── debugger để kiểm tra giả thuyết
   └── viết script tái hiện thuật toán (giải mã, kiểm tra...)

6. Tổng hợp
   ├── viết báo cáo: chức năng, IOC, thuật toán, điểm yếu
   └── lưu database, xuất IDC dump, script đã viết
```

### 24.10. Quy trình phân tích DLL

- Xem **Exports** để biết hàm công khai; `DllMain` (tham số `fdwReason`: 1 = PROCESS_ATTACH).
- Để debug DLL: **Process options → Application** = chương trình nạp DLL (ví dụ `rundll32.exe`),
  **Parameters** = `đường_dẫn.dll,TenHamExport`.
- Bật **Debugger options → Suspend on library load/unload** để dừng khi DLL được nạp.

### 24.11. Quy trình patch diffing (so sánh bản vá)

1. Mở phiên bản cũ, phân tích, lưu `old.i64`.
2. Mở phiên bản mới, lưu `new.i64`.
3. Dùng **BinDiff** hoặc **Diaphora** để so sánh – xem danh sách hàm "matched but changed".
4. Sắp xếp theo mức độ thay đổi, tập trung vào hàm thay đổi nhỏ (thường là chỗ sửa lỗi bảo mật,
   ví dụ thêm một phép kiểm tra độ dài).
5. Phân tích vì sao thay đổi đó cần thiết → hiểu lỗ hổng đã được vá.

---

## 25. Kỹ thuật chống phân tích và cách xử lý

Phần này giúp bạn nhận diện các kỹ thuật làm khó việc phân tích (thường gặp trong mã độc và phần
mềm được bảo vệ) để phân tích chúng trong môi trường nghiên cứu.

### 25.1. Packer

**Dấu hiệu:**

- Rất ít hàm, ít import (chỉ `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`...).
- Section có tên lạ (`UPX0`, `.aspack`, tên ngẫu nhiên) hoặc entropy cao (> 7.0).
- Navigation band phần lớn là dữ liệu/unexplored.

**Xử lý:**

- Packer phổ biến (UPX): dùng công cụ unpack chính thức (`upx -d`).
- Packer tùy chỉnh: debug, đặt breakpoint tại `VirtualAlloc`/`VirtualProtect`, chạy tới khi
  code thật được giải nén, tìm **OEP** (Original Entry Point), dùng memory snapshot hoặc dump
  bằng công cụ ngoài (Scylla, x64dbg), rồi mở bản dump trong IDA.

### 25.2. Mã rác và nhảy chồng lệnh (anti-disassembly)

Ví dụ kinh điển:

```asm
    jz      short loc_1+1
    jnz     short loc_1+1
loc_1:
    db 0E8h                 ; byte rác giả làm lệnh call
    ...
```

IDA (recursive descent) có thể disassemble sai vì byte `E8` bị hiểu là `call`. Cách xử lý:

1. Undefine (`U`) vùng bị sai.
2. Bắt đầu disassemble (`C`) tại `loc_1+1`.
3. Đánh dấu byte rác là dữ liệu (`D`) hoặc patch thành `nop` để decompiler hoạt động.
4. Với nhiều chỗ, viết script tìm mẫu byte và patch tự động.

### 25.3. Opaque predicate

Điều kiện luôn đúng hoặc luôn sai nhưng khó nhận ra tĩnh, ví dụ `if ((x * (x + 1)) % 2 == 0)`
(luôn đúng). Decompiler hiển thị nhánh "chết". Xử lý: patch nhánh không bao giờ chạy, hoặc dùng
plugin deobfuscation dựa trên microcode.

### 25.4. Control flow flattening

Hàm bị biến thành một vòng lặp lớn với `switch` điều phối theo biến trạng thái. Graph view trông
như "cái bàn chải". Xử lý:

- Theo dõi giá trị biến trạng thái để dựng lại thứ tự khối thực.
- Dùng công cụ/plugin chuyên dụng (ví dụ các plugin deobfuscation dựa trên microcode hoặc giả lập
  từng khối).
- Debug + tracing để biết khối nào thực sự được thực thi.

### 25.5. Import ẩn (API hashing)

Code không có import trực tiếp mà duyệt danh sách module trong PEB, tính hash tên hàm, so với
hằng số:

```c
if ( hash_name(export_name) == 0x7C0DFCAA )   // một hash nào đó
    pGetProcAddress = ...;
```

Xử lý:

- Xác định thuật toán hash (ROR13, CRC32, FNV, djb2...).
- Viết script tính hash cho mọi export của các DLL hệ thống, tạo enum `hash → tên API`, áp dụng
  bằng phím `M`.
- Bộ script FLARE có công cụ **shellcode_hashes** làm việc này.

### 25.6. Anti-debug

| Kỹ thuật | Cách nhận biết | Cách vượt qua (trong lab) |
|---|---|---|
| `IsDebuggerPresent` | Import hoặc đọc `PEB->BeingDebugged` (`fs:[30h]+2` / `gs:[60h]+2`) | Patch kết quả, sửa byte trong PEB khi debug |
| `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` | Gọi với `ProcessDebugPort` | Breakpoint và sửa giá trị trả về |
| Kiểm tra thời gian (`rdtsc`, `GetTickCount`) | Hai lần đọc thời gian, so sánh chênh lệch | Patch so sánh, tránh step chậm ở đoạn đó |
| `int 3` / exception | Chương trình tự gây exception, kỳ vọng handler của nó chạy | Cấu hình debugger chuyển exception cho ứng dụng (Debugger options → Exceptions) |
| Kiểm tra checksum code | Đọc vùng `.text` và tính hash | Dùng hardware breakpoint thay vì software breakpoint |
| `NtSetInformationThread(ThreadHideFromDebugger)` | Gọi với class `0x11` | Patch lời gọi |
| TLS callback | Code chạy trước entry point | Kiểm tra Exports/TLS, đặt breakpoint tại TLS callback; bật dừng ở TLS trong debugger options |

Các plugin như **ScyllaHide** (chủ yếu cho x64dbg, có bản cho IDA) ẩn debugger tự động.

### 25.7. Anti-VM

Kiểm tra `cpuid` (bit hypervisor, chuỗi vendor như `VMwareVMware`), tên tiến trình/dịch vụ của
VM, địa chỉ MAC, registry. Dùng `Alt+I` tìm hằng số `0x40000000` (leaf hypervisor của cpuid), hoặc
`Alt+T` tìm chuỗi `"vmware"`, `"vbox"`, `"qemu"`.

### 25.8. Mã hóa chuỗi

Hầu như mọi malware hiện đại đều mã hóa chuỗi. Chiến lược:

1. Tìm hàm giải mã (hàm được gọi rất nhiều lần, nhận con trỏ dữ liệu "lạ").
2. Hiểu thuật toán qua decompiler.
3. Viết script (như ví dụ 20.8) giải toàn bộ và đặt comment.
4. Nếu thuật toán phức tạp, dùng giả lập (Unicorn, flare-emu) để chạy chính hàm giải mã.

---

## 26. Mẹo, thủ thuật và lỗi thường gặp

### 26.1. Thói quen làm việc hiệu quả

1. **Đặt tên ngay khi hiểu**, dù chỉ hiểu một phần (`maybe_parse_cfg`). Tên tạm tốt hơn `sub_XXXX`.
2. **Ưu tiên kiểu dữ liệu**: một struct đúng làm sạch hàng chục hàm cùng lúc.
3. **Đi từ dưới lên**: đặt tên các hàm lá (leaf function – không gọi hàm khác) trước, vì chúng
   thường đơn giản (strlen, memcpy, hash...), sau đó hàm cha sẽ dễ đọc hơn.
4. **Dùng repeatable comment** cho hàm và biến toàn cục quan trọng.
5. **Lưu thường xuyên** (`Ctrl+W`) và tạo snapshot trước các thao tác lớn.
6. **Ghi chú kết luận** trong comment hàm: input, output, tác dụng phụ.
7. **Tô màu** hàm đã xong / đang dở / cần xem lại.
8. **Đừng tin decompiler tuyệt đối** – kiểm chứng ở assembly khi có nghi ngờ.

### 26.2. Database snapshot

**File → Take database snapshot** (`Ctrl+Shift+W`): lưu một bản chụp của database.
**View → Database snapshot manager** (`Ctrl+Shift+T`): xem và khôi phục snapshot. Hãy chụp
trước khi chạy script sửa đổi hàng loạt.

### 26.3. Rebase chương trình

Khi debug, chương trình (đặc biệt có ASLR) có thể nạp tại địa chỉ khác. Để địa chỉ trong IDA khớp
với debugger ngoài (x64dbg, WinDbg):

**Edit → Segments → Rebase program** → nhập base mới (ví dụ `0x7FF6A0000000`).

Hoặc tính **RVA** = địa chỉ − image base để trao đổi địa chỉ giữa các công cụ.

### 26.4. Chuyển thông tin giữa các database

- **File → Produce file → Dump database to IDC file**: sinh script IDC chứa tên, comment, kiểu.
  Chạy script này trên database khác (ví dụ phiên bản mới của cùng chương trình).
- Diaphora/BinDiff có tính năng "import names" từ database khớp.
- Xuất Local Types bằng **Produce file → Create C header file**, nạp lại bằng `Ctrl+F9`.

### 26.5. Lỗi thường gặp

| Lỗi / hiện tượng | Nguyên nhân | Cách khắc phục |
|---|---|---|
| "The input file is not recognized" / chỉ có loader Binary | File thô, file bị hỏng, hoặc định dạng lạ | Chọn processor + địa chỉ nạp thủ công; kiểm tra header |
| Hàm bị cắt ngắn bất thường | Hàm trước đó bị coi là noreturn sai | Bỏ cờ noreturn của hàm callee (`Alt+P`) và phân tích lại |
| Hàm dài bất thường, chứa code của hàm khác | Lời gọi tới hàm noreturn không được nhận diện | Đánh dấu callee là noreturn |
| Decompile báo "call analysis failed" | Không xác định được tham số của lời gọi | Đặt prototype cho callee hoặc dùng **Set call type** tại lời gọi |
| "Decompilation failure: too big function" | Hàm vượt `MAX_FUNCSIZE` | Tăng giá trị trong `hexrays.cfg` |
| Graph view báo quá nhiều node | Hàm quá lớn | Tăng giới hạn trong Options → Graph |
| Không thấy chuỗi Unicode | Strings chỉ quét ASCII | Strings → chuột phải → Setup → bật Unicode |
| IDAPython không khởi động | Sai phiên bản Python / chưa chạy idapyswitch | Chạy `idapyswitch`, kiểm tra Python 64-bit |
| Script cũ lỗi `AttributeError` | Dùng API cũ (trước 7.4) hoặc hàm đã bị loại ở IDA 9 | Đổi sang API mới theo porting guide |
| Debugger không attach được | Thiếu quyền (Linux ptrace, macOS codesign) | Chạy với quyền phù hợp, chỉnh `ptrace_scope`, cấp quyền debug |
| Xref không có cho lời gọi gián tiếp | IDA không biết đích | Thêm xref thủ công / Set callee address |
| Địa chỉ không khớp debugger ngoài | Khác image base (ASLR) | Rebase program hoặc dùng RVA |
| Database bị hỏng sau crash | IDA đóng không đúng cách | Mở lại, chọn khôi phục từ file tạm; dùng bản sao lưu/snapshot |
| Tên bị đổi ngược lại khi phân tích lại | Tên được đánh dấu autogenerated | Đặt tên bằng `N`, bỏ chọn "Autogenerated name" |

### 26.6. Tối ưu hiệu năng với binary lớn

- Tắt các tính năng phân tích không cần trong Kernel options.
- Chia nhỏ: chỉ decompile khi cần, không chạy `Ctrl+F5` cho cả chương trình vài chục nghìn hàm.
- Dùng SSD, nhiều RAM.
- Chạy phân tích ban đầu ở chế độ batch qua đêm, sáng mở database đã có.
- Đóng các cửa sổ cập nhật liên tục (ví dụ cửa sổ xref cố định) khi chạy script lớn.

### 26.7. Mẹo nhỏ hữu ích

- `Ctrl+Shift+P`: command palette – quên phím tắt thì gõ tên lệnh.
- Giữ `Alt` và kéo chuột để chọn khối hình chữ nhật trong một số view.
- Hover chuột lên tên hàm/biến để xem nhanh nội dung (tooltip preview), giữ chuột lâu hơn để xem
  nhiều dòng hơn.
- Trong pseudocode, click giữa (middle-click) hoặc `Ctrl+click` tùy cấu hình để mở trong cửa sổ mới.
- `Shift+;` hoặc menu **Edit → Comments** để quản lý comment.
- `Alt+Enter` hoặc mở thêm IDA View để so sánh hai hàm cạnh nhau.
- **Options → Shortcuts** để xem và tùy chỉnh mọi phím tắt.
- Đặt `idapythonrc.py` để tự import các module hay dùng mỗi khi IDA khởi động:

```python
# IDAUSR/idapythonrc.py
import idc, idautils, idaapi, ida_bytes, ida_funcs, ida_name, ida_kernwin
try:
    import ida_hexrays
except ImportError:
    pass
print("[idapythonrc] Đã nạp các module tiện ích")
```

---

## 27. Bảng phím tắt tổng hợp

> Phím tắt có thể khác nhau đôi chút giữa các phiên bản và hệ điều hành (macOS thường dùng `Cmd`
> thay `Ctrl` ở một số thao tác). Kiểm tra **Options → Shortcuts** để có danh sách chính xác.

### 27.1. Điều hướng

| Phím | Chức năng |
|---|---|
| `G` | Nhảy tới địa chỉ/tên |
| `Esc` | Quay lại |
| `Ctrl+Enter` | Tiến tới |
| `Enter` | Đi theo tham chiếu |
| `Ctrl+P` | Danh sách hàm để nhảy |
| `Ctrl+L` | Nhảy theo tên |
| `Ctrl+E` | Nhảy tới entry point |
| `Ctrl+S` | Nhảy tới segment |
| `Alt+M` / `Ctrl+M` | Đặt bookmark / danh sách bookmark |
| `Space` | Chuyển Text ↔ Graph view |
| `Tab` | Chuyển Disassembly ↔ Pseudocode |

### 27.2. Cửa sổ

| Phím | Cửa sổ |
|---|---|
| `F5` | Pseudocode |
| `Shift+F12` | Strings |
| `Shift+F4` | Names |
| `Shift+F7` | Segments |
| `Shift+F1` | Local Types |
| `Shift+F11` | Type libraries |
| `Shift+F5` | Signatures |
| `Shift+F2` | Script command |
| `Alt+F7` | Chạy script file |
| `Ctrl+Shift+P` | Command palette |

### 27.3. Định nghĩa dữ liệu

| Phím | Chức năng |
|---|---|
| `C` | Code |
| `D` | Data (xoay vòng kích thước) |
| `A` | Chuỗi ASCII |
| `Alt+A` | Chọn kiểu chuỗi |
| `U` | Undefine |
| `*` | Mảng |
| `P` | Tạo hàm |
| `Alt+P` | Sửa hàm |
| `E` | Đặt cuối hàm |
| `O` | Offset |
| `H` / `B` / `R` / `Q` | Hex-dec / Binary / Char / Hex |
| `M` | Enum |
| `T` | Offset struct |
| `Y` | Đặt kiểu C |
| `Alt+G` | Giá trị segment register (ARM Thumb) |
| `Alt+K` | Sửa stack pointer |

### 27.4. Đặt tên và comment

| Phím | Chức năng |
|---|---|
| `N` | Đổi tên |
| `:` | Comment thường |
| `;` | Comment lặp lại |
| `Insert` | Dòng comment phía trên |
| `Shift+Insert` | Dòng comment phía dưới |
| `/` | Comment trong pseudocode |

### 27.5. Tham chiếu và tìm kiếm

| Phím | Chức năng |
|---|---|
| `X` | Xref tới |
| `Ctrl+J` / menu | Xref từ |
| `Alt+T` / `Ctrl+T` | Tìm text / tiếp |
| `Alt+B` / `Ctrl+B` | Tìm byte / tiếp |
| `Alt+I` / `Ctrl+I` | Tìm immediate / tiếp |
| `Ctrl+U` | Byte unexplored tiếp theo |
| `Ctrl+F` | Lọc trong danh sách |

### 27.6. Pseudocode

| Phím | Chức năng |
|---|---|
| `N` | Đổi tên |
| `Y` | Đổi kiểu |
| `/` | Comment |
| `\` | Ẩn/hiện cast |
| `=` | Map biến |
| `Alt+Y` | Chọn thành viên union |
| `H` / `R` / `M` | Hex / Char / Enum |
| `X` | Xref |
| `F5` | Refresh |

### 27.7. Debugger

| Phím | Chức năng |
|---|---|
| `F9` | Chạy / tiếp tục |
| `F2` | Breakpoint |
| `F7` | Step into |
| `F8` | Step over |
| `Ctrl+F7` | Run until return |
| `F4` | Run to cursor |
| `Ctrl+F2` | Dừng tiến trình |
| `Ctrl+Alt+B` | Danh sách breakpoint |
| `Ctrl+N` | Đặt IP tại con trỏ |

### 27.8. Database

| Phím | Chức năng |
|---|---|
| `Ctrl+W` | Lưu database |
| `Ctrl+Shift+W` | Chụp snapshot |
| `Ctrl+Shift+T` | Quản lý snapshot |
| `Ctrl+Z` / `Ctrl+Shift+Z` | Undo / Redo |
| `Ctrl+F9` | Parse C header |
| `Ctrl+F5` | Xuất file C |
| `Alt+F10` | Xuất file ASM |

---

## 28. Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| **Disassembler** | Công cụ chuyển mã máy thành hợp ngữ |
| **Decompiler** | Công cụ chuyển mã máy thành mã cấp cao (giống C) |
| **Database (IDB/I64)** | File lưu toàn bộ kết quả phân tích của IDA |
| **Segment** | Vùng địa chỉ liên tục có cùng thuộc tính (code, data...) |
| **Section** | Khái niệm của định dạng file (PE/ELF); IDA thường ánh xạ section thành segment |
| **EA (Effective Address)** | Địa chỉ trong IDA, kiểu `ea_t` |
| **Head** | Mục bắt đầu (một lệnh hoặc một mục dữ liệu) |
| **Basic block** | Chuỗi lệnh chạy liên tục, chỉ có một lối vào và một lối ra |
| **Xref** | Tham chiếu chéo – thông tin ai dùng địa chỉ nào |
| **FLIRT** | Công nghệ nhận diện hàm thư viện bằng chữ ký |
| **FLAIR** | Bộ công cụ tạo chữ ký FLIRT |
| **TIL** | Type Information Library – thư viện kiểu |
| **Lumina** | Dịch vụ chia sẻ metadata hàm |
| **Ctree** | Cây cú pháp của pseudocode trong Hex-Rays |
| **Microcode** | Biểu diễn trung gian của Hex-Rays |
| **Thunk** | Hàm chỉ chuyển tiếp sang hàm khác |
| **Prologue / Epilogue** | Đoạn code đầu/cuối hàm thiết lập và dọn stack frame |
| **Calling convention** | Quy ước truyền tham số và trả kết quả |
| **IAT** | Import Address Table của PE |
| **PLT / GOT** | Cơ chế gọi hàm thư viện động của ELF |
| **OEP** | Original Entry Point – điểm vào thật sau khi unpack |
| **RVA** | Relative Virtual Address – địa chỉ tương đối so với image base |
| **ASLR** | Ngẫu nhiên hóa không gian địa chỉ |
| **PIE** | Position Independent Executable |
| **Packer** | Công cụ nén/mã hóa chương trình, giải nén khi chạy |
| **Obfuscation** | Làm rối code để khó phân tích |
| **Opaque predicate** | Điều kiện có giá trị cố định nhưng khó nhận biết tĩnh |
| **Patch diffing** | So sánh hai phiên bản để tìm thay đổi (thường là bản vá lỗi) |
| **Recursive descent** | Thuật toán disassemble theo luồng điều khiển |
| **Linear sweep** | Thuật toán disassemble tuần tự từng byte |
| **Literal pool** | Vùng hằng số đặt cạnh code (ARM) |
| **Delay slot** | Lệnh sau lệnh nhảy luôn được thực thi (MIPS) |
| **Stack string** | Chuỗi được dựng từng phần trên stack để né phát hiện |

---

## 29. Tài liệu tham khảo và lộ trình học

### 29.1. Tài liệu chính thức

- Trang chủ Hex-Rays: `https://hex-rays.com` – tải về, so sánh phiên bản, blog kỹ thuật.
- Tài liệu IDA: `https://docs.hex-rays.com` – hướng dẫn sử dụng, ghi chú phát hành.
- Tài liệu IDAPython API: `https://python.docs.hex-rays.com`.
- IDA SDK và ví dụ trên GitHub của Hex-Rays (repository `HexRaysSA`).
- Blog "Igor's tip of the week" của Hex-Rays – hàng trăm mẹo ngắn, rất đáng đọc.

### 29.2. Sách

- *The IDA Pro Book* (Chris Eagle) – sách kinh điển về IDA (bản cũ về API, nhưng khái niệm vẫn đúng).
- *Practical Malware Analysis* (Sikorski & Honig) – nhiều bài lab dùng IDA.
- *Practical Reverse Engineering* (Dang, Gazet, Bachaalany) – x86, x64, ARM, kernel Windows.
- *Reverse Engineering for Beginners* (Dennis Yurichev) – miễn phí, rất nhiều ví dụ assembly.
- *Hacking: The Art of Exploitation* (Jon Erickson) – nền tảng assembly và bộ nhớ.

### 29.3. Nơi luyện tập (hợp pháp)

- **crackmes.one** – kho crackme do cộng đồng tạo.
- **picoCTF**, **pwn.college**, **Flare-On Challenge** (Mandiant, tổ chức hằng năm).
- **Malware Traffic Analysis**, **MalwareBazaar** – mẫu mã độc cho nghiên cứu (chỉ dùng trong
  môi trường cô lập, tuân thủ quy định).
- Tự viết chương trình C, biên dịch với các mức tối ưu khác nhau (`-O0`, `-O2`, `-Os`) và so sánh
  kết quả trong IDA – cách học nhanh nhất để hiểu compiler sinh code thế nào.

### 29.4. Lộ trình học đề xuất

| Giai đoạn | Mục tiêu | Thời gian gợi ý |
|---|---|---|
| 1. Nền tảng | Assembly x86/x64, calling convention, PE/ELF, dùng debugger cơ bản | 2–4 tuần |
| 2. Làm quen IDA | Giao diện, điều hướng, đặt tên, comment, xref, strings | 1–2 tuần |
| 3. Phân tích tĩnh | Struct, kiểu dữ liệu, decompiler, giải crackme đơn giản | 3–6 tuần |
| 4. Phân tích động | Debugger IDA, breakpoint điều kiện, tracing | 2–4 tuần |
| 5. Tự động hóa | IDAPython: duyệt hàm, xref, giải mã chuỗi, viết plugin nhỏ | 4–8 tuần |
| 6. Chuyên sâu | Unpacking, deobfuscation, kiến trúc khác (ARM/MIPS), patch diffing, microcode | Liên tục |

### 29.5. Bài tập tự luyện

1. Biên dịch một chương trình "Hello World" ở `-O0` và `-O2`, so sánh hàm `main` trong IDA.
2. Viết chương trình có một `struct` và hàm thao tác struct, strip symbol, rồi khôi phục struct trong IDA.
3. Viết chương trình có `switch` 10 nhánh, quan sát cách IDA nhận diện jump table.
4. Viết lớp C++ có hàm ảo, phân tích vtable trong IDA.
5. Giải 5 crackme cấp độ dễ trên crackmes.one chỉ bằng phân tích tĩnh.
6. Viết script IDAPython liệt kê mọi hàm gọi `strcpy`/`sprintf`/`gets` (các hàm dễ gây tràn bộ đệm).
7. Viết script xuất đồ thị gọi hàm ra định dạng DOT và vẽ bằng Graphviz.
8. Tạo chữ ký FLIRT cho một thư viện tĩnh bạn tự biên dịch, áp dụng lên chương trình liên kết với nó.
9. Debug từ xa một chương trình Linux từ IDA chạy trên Windows (hoặc ngược lại).
10. Tham gia Flare-On và cố gắng giải ít nhất ba bài đầu.

Gợi ý cho bài tập 6:

```python
import idc, idautils

DANGEROUS = ["strcpy", "strcat", "sprintf", "gets", "vsprintf", "scanf",
             "lstrcpyA", "lstrcpyW", "wcscpy"]

for name in DANGEROUS:
    for candidate in (name, "_" + name, "__imp_" + name, "." + name):
        ea = idc.get_name_ea_simple(candidate)
        if ea == idc.BADADDR:
            continue
        for ref in idautils.CodeRefsTo(ea, 0):
            print("%-10s được gọi tại %08X trong %s" % (name, ref, idc.get_func_name(ref)))
```

Gợi ý cho bài tập 7:

```python
import idc, idautils, ida_funcs

lines = ["digraph callgraph {", "  node [shape=box, fontname=Consolas];"]
for func_ea in idautils.Functions():
    caller = idc.get_func_name(func_ea)
    callees = set()
    for ea in idautils.FuncItems(func_ea):
        for ref in idautils.CodeRefsFrom(ea, 0):
            f = ida_funcs.get_func(ref)
            if f and f.start_ea == ref:          # chỉ lấy lời gọi tới đầu hàm
                callees.add(idc.get_func_name(ref))
    for c in sorted(callees):
        lines.append('  "%s" -> "%s";' % (caller, c))
lines.append("}")

with open("callgraph.dot", "w") as f:
    f.write("\n".join(lines))
print("Đã ghi callgraph.dot – vẽ bằng: dot -Tsvg callgraph.dot -o callgraph.svg")
```

---

## Lời kết

IDA là công cụ có đường cong học tập dốc, nhưng mọi kỹ năng đều xoay quanh một vòng lặp đơn giản:
**quan sát → đặt giả thuyết → ghi lại tri thức vào database (tên, kiểu, comment) → kiểm chứng**.
Mỗi lần bạn đặt đúng một tên hay một kiểu, IDA lan truyền nó ra toàn bộ chương trình, và bức tranh
dần trở nên rõ ràng.

Hãy bắt đầu với những chương trình nhỏ do chính bạn viết, luyện phím tắt cho đến khi thành phản
xạ, rồi dần tiến tới tự động hóa bằng IDAPython. Chúc bạn học tốt và luôn sử dụng kiến thức dịch
ngược một cách hợp pháp, có trách nhiệm.

*Tài liệu được soạn dựa trên các tính năng của IDA từ bản 7.x đến 9.x. Giao diện, tên menu và phím
tắt có thể thay đổi theo phiên bản – hãy đối chiếu với tài liệu chính thức của Hex-Rays.*
