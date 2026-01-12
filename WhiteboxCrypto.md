Việc sử dụng AES trong mã hóa data trong mobile application sẽ cần quan tâm một vấn đề khác là bảo vệ secret key, vì client cũng cần sử dụng key này để giải mã nên bắt buộc phải lưu ở đâu đó trong client, thường là "giấu" trong Native. Tuy nhiên vẫn có nguy cơ bị attacker thực hiện reverse và tìm ra secret key. Whitebox crypto là một dạng mã hóa nâng cao của AES, giúp cải thiện nhược điểm dễ lộ secret key, ý tưởng chính là biến việc mã hóa và giải mã trở thành việc "look up table". Ví dụ: ký tự A ở trong look up table sẽ phải mã hóa thành ký tự X. Như vậy, nếu control được các look up table này và tăng số lượng lên -> từ việc sử dụng secret để mã hóa và giải mã, attacker cần thu thấp hàng nghìn, chục nghìn các table và hiểu được thứ tự sử dụng look up cho việc mã hóa và giải mã.

# AES cơ bản

Ví dụ: https://viblo.asia/p/symmetric-ciphers-mat-ma-doi-xung-aes-phan-2-obA46d1wLKv

# Tìm $K_0$ dựa vào $K_i$

Lấy ví dụ AES-128, chúng ta biết rằng ở bước expand key, chúng ta mở rộng key thêm 10 phần, thu được $K_0$ (chính là secret key) đến $K_{10}$.

to be continue ...
