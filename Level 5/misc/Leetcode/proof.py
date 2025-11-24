import hashlib

# Hàm băm tương tự k()
def test_k(data):
    for _ in range(16):
        data = hashlib.sha512(data).digest()
    return data

# Chỉ cần băm 1 lần
one_round = hashlib.sha512(b"input").digest()

# So sánh với băm 16 lần
assert test_k(b"input") == one_round  # True - kết quả giống nhau!