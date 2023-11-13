---
typora-copy-images-to: img
typora-root-url: ./
---

# PWN

## 环境搭建

工具：

```
可能需要：sudo apt-get install nasm,gcc,gdb,binutils,hexedit
pwntools
vim
pwndbg
python3
libcSeacher git clone http://github.com/lieanu/LibcSearcher.git && python setup.py install
32bit运行时 sudi apt-get install libc6-dev-i386
```



## gcc

```bash
-Og     # 不优化的代码
-m64    # 生成64位的代码
-m32    # 生成32位的代码
-o [fname]   # 指定输出文件
```



## ret2libc

**基本思路**

1.利用一个程序已经执行过的函数去泄露它在程序中的地址，然后取末尾3个字节，去找到这个程序所使
用的libc的版本。

2.程序里的函数的地址跟它所使用的libc里的函数地址不一样，程序里函数地址=libc里的函数地址+偏移
量，在1中找到了libc的版本，用同一个程序里函数的地址-libc里的函数地址即可得到偏移量

3.得到偏移量后就可以推算出程序中其他函数的地址，知道其他函数的地址之后我们就可以构造rop去执
行system（’/bin/sh‘）这样的命令



## 格式化字符串

函数原型：

int printf(const char*, argv[0], ... ...);

返回值是正确输出的字符个数

### 基本利用思路

```
AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x......   # 输出栈中数据，从esp往下输出

# 在linux下有效，在windows下无效的直接取参数的方法：
%<number>$x  是直接读取第number个位置的参数，同样可以用在%n，%d等等。

可以利用%{number}$n给栈中数据赋值
```

例子：

![image-20211115082922190](/img/image-20211115082922190.png)



## 堆利用

### 基础知识

#### ptmalloc - glibc

第一次malloc的情况：

![image-20211121190328397](/img/image-20211121190328397.png)

![image-20211121190405763](/img/image-20211121190405763.png)





malloc_chunk结构体

```cpp
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

一般来说，`size_t` 在 64 位中是 64 位无符号整数，32 位中是 32 位无符号整数。