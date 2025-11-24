# Simple Math Challenge
### Tóm Tắt Lời Giải

Bài toán yêu cầu chúng ta tìm 3 số nguyên `a, b, c` sao cho một dãy số được tạo ra từ chúng có 80 số hạng đầu tiên đều là số nguyên tố. Dãy số này tuân theo một quy luật của một đa thức bậc hai. Lời giải nằm ở việc tìm ra một đa thức sinh số nguyên tố nổi tiếng và đối chiếu hệ số để tìm ra 3 số đầu vào.

**Input cần nhập là: `1601 -78 2`**

---

### Phân Tích Chi Tiết

#### Bước 1: Phân Tích Hàm `check(int n)`

Hàm này là trái tim của bài toán. Thoạt nhìn, nó có vẻ khó hiểu do sử dụng `goto` và các phép toán bit lạ. Hãy cùng "dịch" nó sang dạng dễ đọc hơn.

**Code gốc:**
```c
int check(int n)
{
    int i;i^=i;i|=2;
    if(n<=0)goto b;
    if(n&1&&!(n>>1))goto b;
    c:if(i*i>n)goto a;if(!(n%i))goto b;i++;goto c;
    a:return 1;
    b:return 0;
}
```

**Phân tích từng dòng:**
1.  `int i;i^=i;i|=2;`
    *   `i^=i;` tương đương `i = i ^ i;`, kết quả luôn là `0`.
    *   `i|=2;` tương đương `i = i | 2;`, tức là `i = 0 | 2;`, kết quả là `i = 2`.
    *   Vậy dòng này chỉ là một cách viết phức tạp cho `int i = 2;`.

2.  `if(n<=0)goto b;`
    *   Nếu `n` nhỏ hơn hoặc bằng 0, nhảy đến nhãn `b`. Nhãn `b` trả về `0`.
    *   Điều kiện: `n` phải lớn hơn 0.

3.  `if(n&1&&!(n>>1))goto b;`
    *   `n&1`: Kiểm tra xem `n` có phải là số lẻ không.
    *   `!(n>>1)`: `n>>1` là phép chia `n` cho 2. Phép toán này chỉ trả về 0 khi `n` là 0 hoặc 1. `!` là phép phủ định, vậy `!(n>>1)` chỉ đúng khi `n` là 1.
    *   Kết hợp lại, `n&1 && !(n>>1)` chỉ đúng khi `n` vừa là số lẻ, vừa làm cho `!(n>>1)` đúng, tức là **`n == 1`**.
    *   Điều kiện: `n` không được bằng 1.

4.  `c:if(i*i>n)goto a;if(!(n%i))goto b;i++;goto c;`
    *   Đây là một vòng lặp được viết bằng `goto`.
    *   `c:` là điểm bắt đầu vòng lặp.
    *   `if(i*i>n)goto a;`: Nếu `i*i > n`, thoát vòng lặp và nhảy đến `a`. Nhãn `a` trả về `1`. Đây là một cách tối ưu hóa thường thấy trong thuật toán kiểm tra số nguyên tố.
    *   `if(!(n%i))goto b;`: `n%i` là phép chia lấy dư. `!(n%i)` đúng khi `n % i == 0`, tức là `n` chia hết cho `i`. Nếu `n` chia hết cho `i`, nhảy đến `b` (trả về `0`).
    *   `i++;goto c;`: Tăng `i` lên 1 và lặp lại.

**Kết luận về hàm `check(n)`:**
Hàm này kiểm tra xem `n` có phải là **số nguyên tố** hay không.
*   Nó trả về `1` (true) nếu `n` là số nguyên tố.
*   Nó trả về `0` (false) nếu `n` không phải là số nguyên tố (bao gồm `n <= 1` và các hợp số).

---

#### Bước 2: Phân Tích Hàm `main()`

Hàm `main` đọc 3 số nguyên và thực hiện một vòng lặp 80 lần.

```c
int main(void)
{
    // ...
    int coeff[3];
    printf("Input: ");
    for (int i = 0; i < 3; i++)
        scanf("%4d", &coeff[i]); // Đọc 3 số nguyên
    // ...
    for (int i = 0; i < 80; i++)
    {
        if (!check(coeff[0])) // Nếu coeff[0] không phải số nguyên tố
        {
            printf("Wrong!\n"); // Thoát
            return 0;
        }
        coeff[0] += coeff[1]; // Cập nhật coeff[0]
        coeff[1] += coeff[2]; // Cập nhật coeff[1]
    }
    printf("Correct!\n"); // Nếu vòng lặp hoàn thành, in flag
    // ...
}
```

Để chương trình in ra "Correct!", vòng lặp `for` phải chạy đủ 80 lần. Điều này có nghĩa là tại mỗi lần lặp (từ `i=0` đến `i=79`), giá trị của `coeff[0]` **phải là một số nguyên tố**.

Hãy đặt `a = coeff[0]`, `b = coeff[1]`, `c = coeff[2]`. Ta có một dãy số:
*   Tại `i=0`, `a_0 = a` phải là số nguyên tố.
*   Tại `i=1`, `a_1 = a_0 + b_0 = a + b` phải là số nguyên tố.
*   Tại `i=2`, `a_2 = a_1 + b_1 = (a+b) + (b+c) = a + 2b + c` phải là số nguyên tố.
*   ...

---

#### Bước 3: Tìm Ra Quy Luật Toán Học

Dãy số $a_i$ được tạo ra như thế nào?
*   $b_i$ là một cấp số cộng: $b_i = b + i*c$.
*   $a_i$ là tổng của $a$ ban đầu và các số hạng của dãy $b$:
    $a_i = a + \sum_{k=0}^{i-1} b_k = a + \sum_{k=0}^{i-1} (b + k*c)$
    $a_i = a + i*b + c * \frac{i(i-1)}{2}$

Đây là một **đa thức bậc hai** theo biến `i`. Bài toán trở thành: Tìm 3 số nguyên `a, b, c` sao cho đa thức $P(i) = a + i*b + c * i*\frac{i-1}{2}$ tạo ra 80 số nguyên tố liên tiếp cho `i = 0, 1, ..., 79`.

Đây là một vấn đề nổi tiếng trong toán học. Đa thức sinh số nguyên tố nổi tiếng nhất là của Euler: `n^2 + n + 41`, nhưng nó chỉ tạo ra 40 số nguyên tố.

Một đa thức khác, ít nổi tiếng hơn nhưng phù hợp với bài toán này là:
**$P(n) = n^2 - 79n + 1601$**

Đa thức này tạo ra 80 số nguyên tố khác nhau cho `n = 0, 1, ..., 79`.

Bây giờ, chúng ta cần đối chiếu đa thức này với công thức của chúng ta:
$a + i*b + c * \frac{i(i-1)}{2} = i^2 - 79i + 1601$

Để dễ so sánh, ta biến đổi vế phải:
$i^2 - 79i + 1601 = (i^2 - i) - 78i + 1601 = 2 * \frac{i(i-1)}{2} - 78i + 1601$

Bây giờ ta có thể so sánh trực tiếp:
$a + i*b + c * \frac{i(i-1)}{2} = 1601 + i*(-78) + 2 * \frac{i(i-1)}{2}$

Từ đó suy ra:
*   $a = 1601$
*   $b = -78$
*   $c = 2$

Vậy 3 số chúng ta cần nhập vào là `coeff[0] = 1601`, `coeff[1] = -78`, `coeff[2] = 2`.

#### Bước 4: Nhập Input và Lấy Flag

Khi chạy chương trình và nhập `1601 -78 2`, vòng lặp sẽ hoàn thành 80 lần, chương trình sẽ in ra "Correct!" và sau đó là nội dung của file `flag`.