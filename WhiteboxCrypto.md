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

Tương tự vậy ta có thể tính hết các word mở rộng. Tham khảo code generate tự động:

```
#Ben Ryan
#AES Key Expansion
#Program uses provided key as input, outputs the corresponding keywords w0 - w43 as given in table to cmd

sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

Rcon = [0x00000000, 0x01000000, 0x02000000,
		0x04000000, 0x08000000, 0x10000000, 
		0x20000000, 0x40000000, 0x80000000, 
		0x1b000000, 0x36000000]
		
def keyExpansion(key):
	#prep w list to hold 44 tuples
	w = [()]*44
	
	#fill out first 4 words based on the key
	for i in range(4):
		w[i] = (key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
		
	#fill out the rest based on previews words, rotword, subword and rcon values
	for i in range(4, 44):
		#get required previous keywords
		temp = w[i-1]
		word = w[i-4]

		#if multiple of 4 use rot, sub, rcon etc
		if i % 4 == 0:
			x = RotWord(temp)
			y = SubWord(x)
			rcon = Rcon[int(i/4)]

			temp = hexor(y, hex(rcon)[2:])
			if i == 4:
			    print("x = RotWord(temp)   " + str(x))
			    print("y = SubWord(x)      " + str(y))
			    print("rcon = Rcon[int(i/4)] " + str(rcon))
			    print("word = w[i-4]     " + str(word))
			
		#creating strings of hex rather than tuple
		word = ''.join(word)
		temp = ''.join(temp)
		
		#xor the two hex values
		xord = hexor(word, temp)
		w[i] = (xord[:2], xord[2:4], xord[4:6], xord[6:8])
		
	return w
	
#takes two hex values and calculates hex1 xor hex2
def hexor(hex1, hex2):
	#convert to binary
	bin1 = hex2binary(hex1)
	bin2 = hex2binary(hex2)
	
	#calculate
	xord = int(bin1, 2) ^ int(bin2, 2)
	
	#cut prefix
	hexed = hex(xord)[2:]
	
	#leading 0s get cut above, if not length 8 add a leading 0
	if len(hexed) != 8:
		hexed = '0' + hexed
		
	return hexed
	
#takes a hex value and returns binary
def hex2binary(hex):
	return bin(int(str(hex), 16))

	
#takes from 1 to the end, adds on from the start to 1
def RotWord(word):
	return word[1:] + word[:1]
		
		
#selects correct value from sbox based on the current word
def SubWord(word):
	sWord = ()
	
	#loop throug the current word
	for i in range(4):
		
		#check first char, if its a letter(a-f) get corresponding decimal
		#otherwise just take the value and add 1
		if word[i][0].isdigit() == False:
			row = ord(word[i][0]) - 86
		else:
			row = int(word[i][0])+1

		#repeat above for the seoncd char
		if word[i][1].isdigit() == False:
			col = ord(word[i][1]) - 86
		else:
			col = int(word[i][1])+1
		
		#get the index base on row and col (16x16 grid)
		sBoxIndex = (row*16) - (17-col)
		
		#get the value from sbox without prefix
		piece = hex(sbox[sBoxIndex])[2:]
		
		#check length to ensure leading 0s are not forgotton
		if len(piece) != 2:
			piece = '0' + piece
		
		#form tuple
		sWord = (*sWord, piece)
		
	#return string
	return ''.join(sWord)

#used to display the keywords neatly in this form: w0 = 0f 15 71 c9
def prettyPrint(w):
	print("\n\nKeywords: \n")

	for i in range(len(w)):
		print("w" + str(i), "=", w[i][0], w[i][1], w[i][2], w[i][3])
	
def main():
	#hardcoding input key for demonstration purposes, could be read in from user/program via cmd/gui etc.
	key = ["2b", "7e", "15", "16", "28", "ae", "d2", "a6", "ab", "f7", "15", "88", "09", "cf", "4f", "3c"]

	#expand key
	w = keyExpansion(key)
	
	#display nicely
	print("Key provided: " + "".join(key))
	prettyPrint(w)
	

if __name__ == '__main__':
	main()
```

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

...
