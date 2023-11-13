# linux运维

## 查看一些基本信息

内存大小：cat /proc/meminfo

cpu信息：cat /proc/cpuinfo

关机/重启：poweroff/reboot

查看磁盘空间：df -h

打开管理员权限的shell：sudo -s或者-i

看网络服务状态：netstat -ntlp [ip tcp listening pid]

切换用户：su root (switch user)

## 目录结构

目录 == 文件夹
cd change directory  ..返回上一级目录
pwd 列出当前工作目录
ls list 列出当前工作目录中的内容
/ 操作系统的起始路径
/bin 普通用户和管理员都可以执行的命令
/sbin 只有管理员才能执行的命令 关机重启
/boot 引导 主引导目录 独立的分区 启动菜单 内核
/dev device设备 设备文件存放目录
/etc 配置文件存放目录
/home 普通用户的家目录
/root 管理员的家目录
/media 光驱的挂载目录
/mnt 临时设备的挂载目录
/proc 里面的数据都在内存中，进程的所在目录
/tmp 临时文件存放目录
/usr 软件的安装目录
/var 常变文件存放目录 日志文件 邮件文件

## 快捷键

ctrl+l 清屏
tab 补全命令
ctrl+c 终止命令

## 文件类型

蓝色 目录
黑色 普通文件 可以cat
浅蓝色 符号链接（快捷方式）
黑底黄字 设备文件 硬盘 sda 
绿色 带有执行文件的权限
红色 压缩包文件
紫色 图片 模块文件

## 基本命令

查询：查看目录下有哪些内容。查看文件中的内容 ls/cat
增：创建文件 创建目录
touch 文件名
echo "hello" > 文件
mkdir 目录名 创建目录
改：剪切和复制
mv 剪切、重命名
cp 复制文件 copy
符号链接 ln -s 绝对路径源文件 建立的链接文件
删除 rm -f 1.txt 强制删除文件
rm -rf class 递归删除文件夹 删除目录

命令字的帮助信息查询：
linux命令字格式：
命令字 【选项】 【文件或者目录】
1.如何查看一个命令字的帮助手册
man ls
-a 显示隐藏文件
-l 显示详细信息
-lh 显示文件大小
-R  递归显示

内部命令 命令解释器自带的命令 help cd
外部命令 安装的第三方软件自带的命令字 基本都有帮助手册

## 压缩和解压缩

建立一个大小为100m的文件 /tmp目录 bigfile
dd if=/dev/zero of=/tmp/bigfile bs=1M count=100
inputfile
outputfile
bs单位
count计数器
压缩方式：gzip、bzip2
gzip压缩文件
gunzip解压缩文件
bzip2/bunzip2
(红色的文件是压缩包)
查看目录大小：du -sh 目录名

如何对目录进行"打包"压缩
两个步骤
工具tar--> tar -cf /tmp/allfile.tar /tmp/allfile
tar -cf 生成文件 源文件
tar -xf 要解包的文件 -C 解包目录
createfile
tar -tvf allfile.tar    -->查看打包的里面的信息
tar -zcf 生成文件 源文件 -->同时打包压缩
tar -zxf 要解包的文件 -C 解包目录 -->同时解包解压
-x 解包
-C 制定解压路径
-z -->gzip
-j -->bzip2

## vim编辑器(vi):

命令模式-->输入模式（i）
命令模式-->末行模式（:）
输入模式-->命令模式（esc）
末行模式：wq write quit
q!不保存退出
set nu 显示行号
% s/old/new/g 每一行中的old换成new
命令模式快捷键：
2yy 复制当前行以及下一行
p 粘贴到当前行下
dd 删除当前行
gg 回到第一行
G 回到最后一行
50G 到50行
11dd 删除下面11行
:50,55d -->删除50-55行
文件编码问题：
在vim中set fileencoding=utf-8
od可以查看文件源码之类的

linux操作系统的软件安装
软件分类
源码包 封装后的软件包
源码包的特点
1.以压缩包的形式提供
2.开源

安装的注意事项（源码包）
1.解包
2.//编译 可以指定安装路径个编译所需要的功能
3.进入解压路径了解软件作用以及安装方法
 $ ./configure --prefix=PREFIX 指定安装路径
 $ make
 $ make install
 $ PREFIX/bin/apachectl start
4.make 控制makefile文件进行顺序编译
5.将编译好的文件拷贝到安装路径下
ss -antpl | grep 80

封装后的软件包
安装便捷
后缀名rpm redhat
deb debian
/media/光盘/Packages
ls | grep "tree"
安装注意事项
1.我有没有装过这个软件
 rpm -qa所有软件
2.确认该软件的作用
 rpm -qpi 软件包
3.确认软件的安装路径
 rpm -qpl 软件包
4.安装软件
 rpm -ivh 软件包
5.使用软件
 tree /boot
6.软件卸载
 rpm -e tree

卸载vim编辑器工具
1.该软件的名称
rpm -qa | grep "vim"
2.卸载
rpm -e vim-enhances
光盘中有依赖关系列表 /repodata/	

yum安装
wget更新yum源
1.列出所有可更新的软件清单命令：yum check-update
2.更新所有软件命令：yum update
3.仅安装指定的软件命令：yum install <package_name>
4.仅更新指定的软件命令：yum update <package_name>
5.列出所有可安裝的软件清单命令：yum list
6.删除软件包命令：yum remove <package_name>
7.查找软件包 命令：yum search <keyword>
8.清除缓存命令:
yum clean packages: 清除缓存目录下的软件包
yum clean headers: 清除缓存目录下的 headers
yum clean oldheaders: 清除缓存目录下旧的 headers
yum clean, yum clean all (= yum clean packages; yum clean oldheaders) :清除缓存目录下的软件包及旧的headers

pip：
更换为豆瓣的源
pip install -i https://pypi.douban.com/simple <需要安装的包>

linux用户分类：
切换用户：su - mzi(switch user)
普通用户-权限比超级管理员低-也可以登录系统
超级管理员
-用户分类和组：
-三个文件： /etc/passwd   /etc/shadow      /etc/group
/etc/passwd:
	保存了操作系统中所有用户的信息
	root:x:0:0:root:/root:/bin/bash
	mzi:x:500:500::/home/mzi:/bin/bash
	解释：
		root : x : 0 : 0 : root : /root : /bin/bash
		字段1：用户名称
		字段2：密码占位符
		字段3：用户的uid 0表示超级用户 500-60000普通用户 1-499(程序用户)
		字段4：基本组的gid-用户必须存在的一个组-先有组才有用户
		字段5：用户信息记录字段
		字段6：用户的家目录
		字段7：用户登录系统后用的命令解释器！
/etc/shadow:
	保存了用户的密码信息(依旧是冒号分割)：
	root:$6$mx1CsgOiHiTlB308$8/f.Q1GYTegXbQX5NoMMjK7gtKyB4Q8f0JO    7y7dnFvD7NhGS9gQdlV05Kcr32GdBpDn.nnnEQKyGp.XH8zXIR.:18350:0:    99999:7:::
		字段1：用户名
		*字段2：加密过的密码(sha512+salt)
		字段3：距离1970年1.1密码最近一次的修改时间
		字段4：密码的最短有效期
		*字段5：密码的最长有效期（建议90天）
		字段6：密码过期前7天警告
		字段7：密码的不活跃日期
		字段8：用户的失效时间
/etc/group:
	系统中的组信息
建立和修改用户：
	groupadd [组名]
	groupmod -g 1000 [组名]
	说明：
		-g基本组
		-G附加组
	建立程序用户：
		useradd -u 250 -s /sbin/nologin -M testeaby
	设定用户密码：
		passwd eaby
		*sudo passwd root(用于修改root密码)
		chage -M [密码最长有效期]
		passwd -l eaby上锁
		passwd -u eaby解锁
	删除用户：
		userdel -r(家目录和文件) testeaby
	删组:
		groupdel test1
调整文件以及目录权限：
	drwxr-xr-x. 2 root root 4096 May 23 15:57 hah
    -rw-r--r--. 1 root root   19 May 23 15:57 test.txt
		       {节点/目录中的子目录个数}{所属者}{所属组}
	详细：

		-  rw-  r--  r--  .
		字段1：文件类型：
			d 目录
			l 符号链接(快捷方式)
			b 块设备
		字段2：文件所述者的权限
			文件：r(read)w(write)x(执行)
			目录：r(查看目录内容)w(添加删除文件)x(可以进入目录)
		字段3：文件所属组的权限
		字段4：其他用户的权限（既不是所有者也不是所属组的用户）
	chmod 用户 算术运算符 权限 文件
		用户： u(user_owner) g(group) o(others) a(all)
		算术运算符：+-=
	改变文件所属：
		chown
		chgrp
	ll命令可以查看文件权限
	粘滞位-sgid-suid权限:
		粘滞位针对目录赋权，目录中创建的文件只有建立者可以删除
			chmod o+t test
			/tmp/
		sgid:
			针对目录
			在该目录中创建的文件的所属组继承父目录的所属组
			chmod g+s test
		suid:
			针对可执行文件
			继承所属者的权限
			chmod u+s /usr/bin/vim--->红底白字警告
	find /usr/bin -perm(权限) 4(suid)755 
	chattr:
		更改文件属性
		chattr +i /etc/passwd  禁止文件修改
		isatter /etc/passwd   查看属性
	创建文件的权限：
		umask
		0022/0002
		/etc/profile
		/etc/bashrc
	默认密码最长有效期天数：
		/etc/login.defs
网络信息配置：
	ip-子网掩码-网关-dns
	1.确认网卡信息和ip地址
		命令：
			ip addr网路设备和状态
			service NetworkManager stop
			配置地址：
				ip addr add 192.168.86.100/24 dev eth0
				ip link set eth0 up(这个方法好像不太好)
				ip route add default via 192.168.86.1 dev eth0
				/etc/resolv.conf -->dns
			通过修改配置文件配置网络：
				/etc/sysconfig/network-scripts/
日志文件：
	/var/log/
	日志分类：
		系统日志:
			/messages
		登录日志
			/secure
		程序日志
	日志的管理服务：
		/etc/rsyslog.conf
	日志的异地备份：
		/etc/rsyslog.conf
		ss -antpl
apache:
	httpd-lamp
	80-443
	启动服务：
		service httpd start
	验证ss -antpl
	主配置文件分析：
		/etc/httpd/httpd.conf
		身份和组
		DocumentRoot-默认主页路径
		文件共享功能：
			Option Indexes FollowSymlinks(删掉indexes)
	访问控制设定：
		Order allow,deny 白名单
		Allow from all/192.168.1.(网段)
	对页面进行加密：
		需要用户名和密码：
			htpasswd -c /etc/httpd/conf/httpuser tom