Việc sử dụng AES trong mã hóa data trong mobile application sẽ cần quan tâm một vấn đề khác là bảo vệ secret key, vì client cũng cần sử dụng key này để giải mã nên bắt buộc phải lưu ở đâu đó trong client, thường là "giấu" trong Native. Tuy nhiên vẫn có nguy cơ bị attacker thực hiện reverse và tìm ra secret key. Whitebox crypto là một dạng mã hóa nâng cao của AES, giúp cải thiện nhược điểm dễ lộ secret key, ý tưởng chính là biến việc mã hóa và giải mã trở thành việc "look up table". Ví dụ: ký tự A ở trong look up table sẽ phải mã hóa thành ký tự X. Như vậy, nếu control được các look up table này và tăng số lượng lên -> từ việc sử dụng secret để mã hóa và giải mã, attacker cần thu thấp hàng nghìn, chục nghìn các table và hiểu được thứ tự sử dụng look up cho việc mã hóa và giải mã.

# AES cơ bản

Ví dụ: https://viblo.asia/p/symmetric-ciphers-mat-ma-doi-xung-aes-phan-2-obA46d1wLKv

# Tìm K0 dựa vào Ki

Lấy ví dụ AES-128, chúng ta biết rằng ở bước expand key, key được mở rộng thêm 10 phần, thu được K0 (chính là secret key) đến K10.

Xem xét bài toán biết K10 có thể tìm được K0 không?

Trước hết, thử expand key theo chiều xuôi, giả sử một ACS secret key là `2b7e1516 28aed2a6 abf71588 09cf4f3c`, tách ra 4 phần, chính là `W0 W1 W2 W3`.

Theo quy tắc (Các hàm và phép toán tham khảo thêm qua [link](https://viblo.asia/p/symmetric-ciphers-mat-ma-doi-xung-aes-phan-2-obA46d1wLKv) hoặc [wiki](https://en.wikipedia.org/wiki/AES_key_schedule)

```
W4
= W0​ xor SubWord(RotWord(W3)) xor rcon1
= 0x2b7e1516 xor SubWord(RotWord(0x09cf4f3c)) xor 0x01000000
= 0x2b7e1516 xor SubWord(0xcf4f3c09) xor 0x01000000
= 0x2b7e1516 xor 0x8a84eb01 xor 0x01000000
= 0xa0fafe17
```

```
W5 = W1 xor W4 = 0x88542cb1
W6 = W2 xor W5 = 0x23a33939
W7 = W3 xor W6 = 0x2a6c7605
```

Tương tự vậy ta có thể tính hết các word mở rộng. Code tự động encrypt có thể tìm kiếm qua Internet.

<img width="1567" height="707" alt="image" src="https://github.com/user-attachments/assets/69dc6c86-45c2-48b3-bc32-af11433bf8b6" />

Các word màu cam tương ứng với quy tắc phức tạp hơn , các word màu xanh lá cây chỉ là phép toán xor đơn giản.

Giả sử chúng ta biết K10 là `d014f9a8 c9ee2589 e13f0cc8 b6630ca6`, có thể dễ dàng tính được:

```
W37 = W40 xor W41 = 0xd014f9a8 xor 0xc9ee2589 = 0x19fadc21
W38 = W41 xor W42 = 0xc9ee2589 xor 0xe13f0cc8 = 0x28d12941
W39 = W42 xor W43 = 0xe13f0cc8 xor 0xb6630ca6 = 0x575c006e
```

Đối với W36, chú ý công thức tính `W40 = W36​ xor SubWord(RotWord(W39)) xor rcon10` hoàn toàn có thể suy ra `W36 = W40 xor SubWord(RotWord(W39)) xor rcon10`

Như vậy, chúng ta có thể tính được K9, tương tự, tính được K8, K7, ... cuối cùng là K0.

Tóm lại, khi biết Ki bất kỳ, chúng ta có thể tìm được secret key K0.

# Whitebox crypto

Để nhìn thấy ưu điểm của whitebox crypto so với AES, cùng nhìn nhận lại quá trình mã hóa AES (lấy AES-128) làm ví dụ:

```
plaintext -> state
AddRoundKey(state, k_0)
for r = 1 ... 9
    SubBytes(state)
	ShiftRows(state)
    MixColumns(state)
	AddRoundKey(state, k_r)
SubBytes(state)
ShiftRows(state)
AddRoundKey(state, k_10)
state -> ciphertext
```

Có thể thấy, các phần key expand chỉ dùng ở bước AddRoundKey, và 2 bước SubBytes, ShiftRows không ảnh hưởng kết quả mã hóa khi hoán đổi thứ tự với nhau trong cùng vòng lặp, nên có thể nhóm lại các vòng lặp theo cách mới:

```
plaintext -> state
for r = 1 ... 9
    AddRoundKey(state, k_{r−1})
    ShiftRows(state)
    SubBytes(state)
    MixColumns(state)
AddRoundKey(state, k_9)
ShiftRows(state)
SubBytes(state)
AddRoundKey(state, k_10)
state -> ciphertext
```

Tiếp tục hoán đổi thứ tự ShiftRows và AddRoundKey cho nhau trong cùng vòng lặp cũng không ảnh hưởng gì:

```
plaintext -> state
for r = 1 ... 9
	ShiftRows(state)
    AddRoundKey(state, k_{r−1})
    SubBytes(state)
    MixColumns(state)
ShiftRows(state)
AddRoundKey(state, k_9)
SubBytes(state)
AddRoundKey(state, k_10)
state -> ciphertext
```

