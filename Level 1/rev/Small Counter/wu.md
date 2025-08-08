Bài này theo như wu thì tui sẽ set giá trị của biến đếm = 5 để nó thực thi đúng hàm `flag_gen()` để tạo ra flag.  
Dùng gdb để debug từ từ, sau khi đọc mã assembly thì ta có công thức sau: `Địa chỉ của local_c = Giá trị của thanh ghi RBP - 4`.  
Áp dụng khi debug ta sẽ lấy giá trị của thanh ghi `rbp` rồi trừ đi `4` để có được đúng địa chỉ của `local_c`.

```bash
>>> hex(0x00007fffffffd8f0 - 4)
'0x7fffffffd8ec'
```

```bash
gef➤  set *0x7fffffffd8ec=5
gef➤  c
Continuing.
Nice!

DH{389998e56e90e8eb34238948469cecd6dd89c04dce359c345e0b2f3ef9edc66a}
[Inferior 1 (process 2794) exited normally]
gef➤
```