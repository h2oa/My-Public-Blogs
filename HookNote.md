## 1. Một số tool cho hook

frida, hluda, florida

Check kiến trúc để tải đúng ver: https://github.com/frida/frida/releases

```
# uname -m

"aarch64" is 64-bit ARMv8-A, which is Android's "arm64-v8a" ABI.
"armv7l" is 32-bit ARMv7-A, which is Android's "armeabi-v7a" ABI.
"x86_64" is 64-bit x86, which is Android's "x86_64" ABI.
"i386" or "i686" are the basic 32-bit x86 or the Pentium Pro variant respectively, which is Android's "x86" ABI.
```

<img width="1078" height="287" alt="image" src="https://github.com/user-attachments/assets/a8e38023-3966-4fae-8fd7-cf86ccfba3cd" />

Frida server thường hay adb push vào `data/local/tmp` trong điện thoại, rồi chạy frida server lên thôi `./frida-server-name &`, dấu `&` để chạy ngầm:

<img width="1184" height="276" alt="image" src="https://github.com/user-attachments/assets/858edc6d-a8ab-405e-92f2-948d7cfbd3be" />

Forward port

```
./frida-server -l 0.0.0.0:1337 &
```

Cài frida client ở máy tính:

```
pip3 install frida==<version> & frida-tools==<version>
frida --version
frida-ps --version
```

Client chạy:

```
frida -U -f <package_name> -l <scrip_path>  -> chạy thường connect qua usb debug
frida -H ip:1337 ...   -> chạy forward port
```

Mở app lên và check các package apk đang chạy:

```
frida-ps -Ua
```

<img width="828" height="287" alt="image" src="https://github.com/user-attachments/assets/9ec1dc4b-46e5-4d4f-ab1e-0a8a1713fe84" />



## 2. Hook Java

Sử dụng jadx decompile apk > Chuột phải vào hàm cần hook > Copy as frida code

## 3. Hook Native

Trong class MainActivity hay có đoạn code gọi thư viện `System.loadLibrary()` chính là đang gọi các lib `.so` Native. Như hình dưới thì gọi lib `hellojni.so` trong `Resources/lib/x86_64` (có thể gọi các lib khác tùy kiến trúc), lưu ý tên lib được ghép tiền tố lib vào:

<img width="825" height="437" alt="image" src="https://github.com/user-attachments/assets/cfa435a8-cbe6-4c15-897b-6777f2cffa70" />

<img width="1721" height="974" alt="image" src="https://github.com/user-attachments/assets/50c5cc8a-f484-461f-b1a7-25139b90f0e5" />

API `Interceptor.attach` nhận tham số là địa chỉ của hàm cần hook trong bộ nhớ android, có 2 event:

- Event onEnter: Thực thi khi hook vào hàm thành công, lúc này đọc tham số truyền vào được.
- Event onLeave: Thực thi khi kết thúc quá trình hook vào hàm, thay đổi được giá trị return.

Đoạn js hook như sau, `addressFunctionHook` là địa chỉ hàm cần hook, cần tìm được địa chỉ này:

```
Interceptor.attach(addressFunctionHook, {
    onEnter: function(args) {
        console.log('Inside stringFromJNI...');
    },
    onLeave: function(retval) {
        const retStr = Java.vm.getEnv().newStringUtf("Hooked Native successfully!");
        retval.replace(retStr);
    }
});
```

Lệnh `nm` có thể lấy được offset address của hàm cần hook. Trước hết decompile apk file trước, rồi dùng cú pháp:

```
nm --demangle --dynamic <đường-dẫn-tới-file-thư-viện>
```

<img width="1460" height="519" alt="image" src="https://github.com/user-attachments/assets/65790ad3-649a-484f-9655-8a5a7d7d9bee" />


Lưu ý `nm` phải chạy đúng lib tương ứng với kiến trúc android, trong trường hợp này phải chạy với kiến trúc arm64-v8a (bảo sao nãy giờ so sánh hai phương pháp địa chỉ không giống nhau):

<img width="1452" height="437" alt="image" src="https://github.com/user-attachments/assets/c8a4657f-22ea-4cfa-8b5a-711d5d0a294a" />

Như hình trên thấy được offset của hàm stringFromJNI là 0x13c28.

Kết hợp API Module.findBaseAddress() thì tính toán được địa chỉ hàm cần hook:

```
var baseAddr = Module.findBaseAddress("libdemo_hook_native.so");
var FuncAddr = baseAddr.add(0x13c28);
```

Full code (có chứa các cách tìm địa chỉ khác)

```
function main() {
    console.log("Start hooking ...");
    setTimeout(function() {
        Java.perform(function() {
            var stringFromJNI = Module.getExportByName('libdemo_hook_native.so', 
                'Java_cyber_sunasterisk_demo_1hook_1native_MainActivity_stringFromJNI');
            console.log("Address with Module.getExportByName: " + stringFromJNI);
            var baseAddr = Module.findBaseAddress("libdemo_hook_native.so");
            var FuncAddr = baseAddr.add(0x13c28);
            console.log("Address with nm: " + FuncAddr);
            Module.enumerateExports("libdemo_hook_native.so", { 
                onMatch: function(e) {
                    if (e.name == "Java_cyber_sunasterisk_demo_1hook_1native_MainActivity_stringFromJNI") {
                        console.log("[+] Function (with Module.enumerateExports): " + e.name + " - Address: " + e.address);
                    }
                }, 
                onComplete: function() { 
                }
            });
            var FuncAddr = DebugSymbol.fromName('Java_cyber_sunasterisk_demo_1hook_1native_MainActivity_stringFromJNI').address;
            console.log("Address with DebugSymbol.fromName: " + FuncAddr);
            var FuncAddr1 = DebugSymbol.findFunctionsMatching('*stringFromJNI*');
            console.log("Address with DebugSymbol.findFunctionsMatching: " + FuncAddr1);
            let addressAll = {
                "test": "0x77187a6c28"
            };
            var addressAllPointer = ptr(addressAll.test);
            Interceptor.attach(addressAllPointer, {
                onEnter: function(args) {
                },
                onLeave: function(retval) {
                    var retStr = Java.vm.getEnv().newStringUtf("Hooked Native successfully!");
                    retval.replace(retStr);
                }
            });
        });
    }, 2000);
}

setImmediate(main);
```

## 4. Thay đổi args truyền vào hàm

Nãy giờ hook vào phần return của stringFromJNI, giờ cụ thể muốn hook vào hàm testString() và xem tham số truyền vào, thay đổi tham số truyền vào.

Liệt kê tham số truyền vào:

```
var baseAddr = Module.findBaseAddress("libdemo_hook_native.so");
var FuncAddr = baseAddr.add(0x13a8c);
Interceptor.attach(FuncAddr, {
    onEnter: function(args) {
        console.log('Args 0: ' + Memory.readUtf8String(args[0]));
        console.log('Args 1: ' + Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
    }
});
```

<img width="1662" height="569" alt="image" src="https://github.com/user-attachments/assets/b2466c51-bdc3-477e-9f45-0b378e0af68c" />


Chưa hiểu vì sao args 0 và 1 đều là "Hello from C++" …

Muốn thay đổi tham số truyền vào thì trong event onLeave gọi lại hàm một lần nữa với tham số mới, chưa hiểu vì sao phải thừa một dấu cách ở trước args mới?

```
function main() {
    console.log("Start hooking ...");
    setTimeout(function() {
        Java.perform(function() {
            var baseAddr = Module.findBaseAddress("libdemo_hook_native.so"); 
            var FuncAddr = baseAddr.add(0x13a8c);
            var testStringNew = new NativeFunction(ptr(FuncAddr), 'pointer', ['pointer']);
            Interceptor.attach(FuncAddr, {
                onEnter: function(args) {
                    console.log('Args 0: ' + Memory.readUtf8String(args[0]));
                    console.log('Args 1: ' + Memory.readUtf8String(args[1]));
                },
                onLeave: function(retval) {
                    const argNew = Memory.allocUtf8String(" hooked new");
                    testStringNew(argNew).readUtf8String();
                }
            });
        });
    }, 2000);
}

setImmediate(main);
```

## Tham khảo

- https://viblo.asia/p/hook-android-native-phan-1-yZjJYjjpLOE
- https://eternalsakura13.com/2020/07/04/frida/
