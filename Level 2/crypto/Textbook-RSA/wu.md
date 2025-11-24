# Textbook-RSA (Dreamhack)

## Giới thiệu

Đây là một bài tấn công RSA kinh điển dựa trên tính chất đồng cấu (homomorphic property). Lỗ hổng nằm ở chỗ server cho phép giải mã bất kỳ bản mã nào ngoại trừ bản mã của flag.

## Phân tích lỗ hổng

### Mã nguồn challenge.py:

- Server sử dụng mã hóa RSA textbook, không có padding.
- Server cung cấp một "oracle giải mã": bạn có thể gửi một bản mã `ct` bất kỳ và nhận lại bản rõ `pt`, miễn là `ct` không phải là bản mã của flag (`FLAG_enc`).

### Tính chất đồng cấu của RSA:

$$
(m_1^e \bmod N) \cdot (m_2^e \bmod N) \bmod N = (m_1 \cdot m_2)^e \bmod N
$$

Điều này cho phép chúng ta "nhân" các bản mã với nhau.

## Ý tưởng tấn công

1. Lấy `N`, `e`, và `FLAG_enc` từ server.
2. Chọn một số nguyên `S` bất kỳ (ví dụ S=2).
3. Tự mã hóa `S` để có `S_enc = pow(S, e, N)`.
4. Tạo một bản mã mới `new_ct = (FLAG_enc * S_enc) % N`.
5. Theo tính chất đồng cấu, `new_ct` chính là bản mã của `(FLAG * S) % N`.
6. Vì `new_ct` khác với `FLAG_enc`, server sẽ chấp nhận giải mã nó.
7. Gửi `new_ct` cho oracle giải mã và nhận lại kết quả `decrypted_new_ct`.
8. `decrypted_new_ct` chính là `(FLAG * S) % N`.
9. Để tìm lại FLAG ban đầu, ta chỉ cần nhân kết quả với nghịch đảo modular của S:
    ```
    FLAG = (decrypted_new_ct * inverse(S, N)) % N
    ```
10. Chuyển FLAG từ số nguyên sang bytes để đọc.