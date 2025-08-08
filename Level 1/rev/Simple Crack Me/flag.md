Flag: `DH{322376503}`

Bài này khi mở Ghidra thì ta sẽ tìm tới hàm có chứa chuỗi `"Correct!"`
```C
bool FUN_00401ad5(void)

{
  long in_FS_OFFSET;
  bool bVar1;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 0;
  FUN_0040bb20(&DAT_004b6004,&local_14);
  bVar1 = local_14 != 0x13371337;
  if (bVar1) {
    FUN_0040b990("%x is wrong x(\n",local_14);
  }
  else {
    FUN_0041a400("Correct!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    FUN_0045a420();
  }
  return bVar1;
}
```

Trong hàm trên, ta thấy rõ logic chính là biến `local_14` là biến user nhập vào (gọi là input), sau đó sẽ được đem đi so sánh với giá trị hex là `0x13371337`.  
Đây chính là flag cần tìm, giờ ta đổi số hex `0x13371337` thành dạng thập phân là `322376503` là đã có kết quả rồi.