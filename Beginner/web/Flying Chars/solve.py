order = [10, 17, 13, 7, 16, 8, 14, 2, 9, 5, 11, 6, 12, 3, 0, 19, 4, 15, 18, 1]

# BẠN CẦN ĐIỀN VÀO ĐÂY
# Hãy mở từng file ảnh và điền ký tự tương ứng vào mảng này.
# Ví dụ: nếu 0.png chứa 'A', 1.png chứa 'B',...
chars = [
    '_', # 0.png
    'x.x', # 1.png
    't', # 2.png
    'h3', # 3.png
    'h4', # 4.png
    'sE', # 5.png
    '_', # 6.png
    '_H', # 7.png
    'rd', # 8.png
    'o_', # 9.png
    'T', # 10.png
    'e', # 11.png
    't', # 12.png
    'o', # 13.png
    '_', # 14.png
    'r', # 15.png
    '4', # 16.png
    'o', # 17.png
    's_', # 18.png
    'C'  # 19.png
]

# Ghép flag
flag = ""
for i in order:
    flag += chars[i]

print(f"Flag: {flag}")
# Đừng quên bọc kết quả trong DH{...}
print(f"Final Flag: DH{{{flag}}}")
# Flag: DH{Too_H4rd_to_sEe_th3_Ch4rs_x.x}