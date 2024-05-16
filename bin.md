---
typora-copy-images-to: img
typora-root-url: ./
---

# WINDOWS

## MFC

本质就是对win32的封装。

最简单的创建使用dialogue base。

通常的配置是静态编译mfc，会方便一些：

​     Project->Setting->设置static lib

### mfc的层次结构图

在msdn里搜Hierarchy Chart。

#### CWinApp类

基于CWinApp的应用程序对象，程序本体，有且只能有一个。

必须要覆盖CWinApp的虚函数InitInstance在里面创建窗口并把窗口对象保存在它里面的成员变量m.pMainWnd。

#### CFrameWnd类

类似于窗口过程函数-消息处理函数。

创建窗口是通过派生这个类。

##### CFrameWnd::Create

BOOL Create(xxxxxxxxxx);

其中如果类名为NULL，则以MFC内建的窗口类产生一个标准的外框窗口。

#### 手动编写mfc程序的几个注意事项

1. 使用win32 application去创建工程
2. 包含MFC运行库，设置静态编译就可以了
3. 使用头文件afxwin.h

##### 基本代码实现

hello.cpp:

```c
#include <afxwin.h>
#include "hello.h"

CMyApp theApp;

BOOL CMyApp::InitInstance()
{
	m_pMainWnd = new CMainWindow;
	m_pMainWnd->ShowWindow(m_nCmdShow);
	m_pMainWnd->UpdateWindow();
	return TRUE;
}

CMainWindow::CMainWindow()
{
	Create(NULL,"helloMFC");
}
```

hello.h:

```c
#ifndef __HELLO_H__
#define __HELLO_H__

class CMyApp:public CWinApp
{
public:
	virtual BOOL InitInstance();
};

class CMainWindow:public CFrameWnd
{
public:
	CMainWindow();
};


#endif
```

### mfc的初始化过程

> 全局变量和全局对象会先于main函数执行

 消息循环在CWinApp::Run()里面实现

### mfc运行时类型识别(RTTI)











## PE

### 导出表

**如何定位导出表**（这段写的不是很清楚）

在扩展pe头的最后一个成员(16个结构体*8bytes)中查找
导出表的属性在第一个结构体中：
第一个DWORD是导出表的RVA，要先转化成FOA
然后就可以找到导出表结构体 

**导出表关键结构体：_IMAGE_EXPORT_DIRECTORY（40bytes）**

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;      // 未使用
    DWORD   TimeDateStamp;
    WORD    MajorVersion;         // 未使用
    WORD    MinorVersion;         // 未使用
    DWORD   Name;                 // 指向导出表文件名字符串
    DWORD   Base;                  // 导出函数起始序号
    DWORD   NumberOfFunctions;     // 所有导出函数个数
    DWORD   NumberOfNames;          // 以名字导出的函数个数
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

**重要的有三张表：**

1. 函数地址表（每个成员4bytes（32位程序），RVA）

2. 函数名称表（RVA）

3. 序号表（2bytes）

   序号表里的成员个数等于函数名称表里的成员个数

**查找函数的原理：**

API函数：

```c
FARPROC GetProcessAddress(
	HMODULE HModule,    //dll模块句柄
    LPCSTR lpProcName    // 函数名
);
```

查找过程：

1. 函数名称表 - 第0个 --> 序号表 - 第0个 --> 序号表第0个的值是4 --> 查函数地址表第4个的位置 === 找到函数
2. 通过序号查找，序号-Base(导出表的开始编号) --> 函数地址表的偏移

### 导入表

#### 确定依赖模块

导入表说明了Pe文件需要依赖哪些模块以及依赖这些模块中的哪些函数。

导入表不是一个，是**一堆**，导入几个模块就有几张导入表。

导入表的结构 _IMAGE_IMPORT_DESCRIPTOR

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;         // 时间戳
    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;            //RVA 指向dll名字，该名字以\0结尾
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

```

整个的宽度是20bytes

*确定导入表数量：查导入表直到20个0x00*

#### 确定依赖函数

_IMAGE_IMPORT_DESCRIPTOR中第一个成员：OriginalFirstThunk，指向INT表(import name table 导入名称表)。

最后一个成员FirstThunk指向IAT表(import address table 导入地址表)。

INT和IAT内容是<u>一样的</u>。

![](/img/导入表.jpg)

INT里头的成员都是结构体(IMAGE_THUNK_DATA->_IMAGE_THUNK_DATA32)

```c
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        PBYTE  ForwarderString;
        PDWORD Function;
        DWORD Ordinal;      //序号
        PIMAGE_IMPORT_BY_NAME  AddressOfData;     //指向IMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
```

宽度是四个字节

有多少成员就是依赖这个dll中的多少个函数。

确定需要导入的函数：

![](/img/导入表2.jpg)

IMAGE_IMPORT_BY_NAME结构体>=3bytes。但是函数名称以00结尾。

#### 确定函数地址

主要是IAT导入地址表。

<u>区别在于pe文件加载前和加载后IAT表发生了变化</u>



### 重定位表

dll加载的时候ImageBase可能会相同然后操作系统负责将它加载在内存的其他地方。

这个时候有的不是RVA的地址就会出问题，如果不修正就没办法用了。

**重定位表就是记录了硬编码中需要修改的地址，如果没有在对应的ImageBase展开，就需要修改**

位置在扩展Pe头的最后一个成员数组中的第六个结构体里（Image_diretory_basereloc）

重定位表的结构体：_IMAGE_BASE_RELOCATION

### 资源表

先找扩展pe头，然后找最后一个成员的第3个成员。

这个成员还是一个rva带一个size。





### 注入shellcode

shellcode是指不依赖环境放在任何地方都能执行的机器码

```bash
编写原则：
1. 不能有全局变量
2. 不能使用常量字符串        # 重点
3. 不能使用系统调用(动态链接)          # 重点
4. 不能嵌套调用其他函数
```

#### 使用常量字符串

```c
char szBuffer[] = {'C','h','i','n','a',0};        // 这样写是ok的
```

#### 使用系统调用(使用dll)

```c
void fun(){
    // fs:[0x30]; -> PEB
    // 找到PEB以后找三个链表，然后遍历三个链表，找到kernel32.dll
    // 然后通过dll的导出表找函数
    // 先整一个GetProcAddress();然后就可以为所欲为了
}
```

### HOOK

用于获取更改程序执行时的某些数据，或者是更改程序的执行流程。

#### 主要的两种形式

1. INLINE HOOK(改代码的)
2. 其他方式(改函数地址)(IAT SSDT IDT EAT IRP)

#### IAT HOOK

导入地址表hook

通过修改IAT来hook。
主要测试代码如下：

1.dll(用于注入的dll):
```cpp
// 1.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"


DWORD g_dwOldAddr;         // 原始函数地址
DWORD g_dwNewAddr;         // Hook函数地址
DWORD g_dwIATHookFlag;     // 标志有没有被hook

BOOL SetIATHook(DWORD dwOldAddr, DWORD dwNewAddr){
	BOOL bFlag = FALSE;
	DWORD dwImageBase = 0;
	PDWORD pFuncAddr = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	DWORD dwOldProtect = 0;

	// 得到exe模块基址
	dwImageBase = (DWORD)GetModuleHandle(NULL);
	pNtHeader = (PIMAGE_NT_HEADERS)(dwImageBase + ((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + 
		pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	// 遍历IAT表 找到这个函数的地址
	while (pImportDescriptor->FirstThunk != 0 && bFlag == FALSE)
	{
		pFuncAddr = (PDWORD)(dwImageBase + pImportDescriptor->FirstThunk);
		while (*pFuncAddr) // 遍历该模块中的函数
		{
			if(dwOldAddr == *pFuncAddr){
				// 找到要Hook的函数，先修改内存页的属性
				VirtualProtect(pFuncAddr, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
				*pFuncAddr = dwNewAddr;   // !!!更改过IAT中函数的地址
				VirtualProtect(pFuncAddr, sizeof(DWORD), dwOldProtect, 0);
				bFlag = TRUE;
				break;
			}
			pFuncAddr ++;
		}
		pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportDescriptor+sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	// 修改状态
	g_dwOldAddr = dwOldAddr;
	g_dwNewAddr = dwNewAddr;
	g_dwIATHookFlag = 1;
	return bFlag;
}        

BOOL UnIATHook(){
	BOOL bFlag = FALSE;
	DWORD dwImageBase = 0;
	PDWORD pFuncAddr = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	DWORD dwOldProtect = 0;

	// 判断是否hook
	if (!g_dwIATHookFlag)
	{
		OutputDebugString("UnIATHook失败：尚未进行IAT Hook!");
		return bFlag;
	}
	
	// 得到exe模块基址
	dwImageBase = (DWORD)GetModuleHandle(NULL);
	pNtHeader = (PIMAGE_NT_HEADERS)(dwImageBase + ((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + 
		pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	// 遍历IAT表 找到这个函数的地址
	while (pImportDescriptor->FirstThunk != 0 && bFlag == FALSE)
	{
		pFuncAddr = (PDWORD)(dwImageBase + pImportDescriptor->FirstThunk);
		while (*pFuncAddr) // 遍历该模块中的函数
		{
			if(g_dwNewAddr == *pFuncAddr){
				// 找到要Hook的函数，先修改内存页的属性
				VirtualProtect(pFuncAddr, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
				*pFuncAddr = g_dwOldAddr;   // !!!更改过IAT中函数的地址
				VirtualProtect(pFuncAddr, sizeof(DWORD), dwOldProtect, 0);
				bFlag = TRUE;
				break;
			}
			pFuncAddr ++;
		}
		pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportDescriptor+sizeof(PIMAGE_IMPORT_DESCRIPTOR));
	}
	// 修改状态
	g_dwOldAddr = 0;
	g_dwNewAddr = 0;
	g_dwIATHookFlag = 1;
	return bFlag;
}       


int WINAPI MyMessageBox(HWND hWnd, LPCSTR lpText,LPCSTR lpCaption, UINT uType){
	char lpNewText[] = "你被hook了";
	// 定义MessageBox函数指针
	typedef int (WINAPI *PFNMESSAGEBOX)(HWND, LPCSTR, LPCSTR, UINT);

	// 执行真正的函数
	int ret = ((PFNMESSAGEBOX)g_dwOldAddr)(hWnd, lpNewText, lpCaption, uType);
	return ret;
}




// 线程函数
DWORD WINAPI ThreadProc(LPVOID lpParameter){
	// 保存原始函数地址
	DWORD pOldFuncAddr = (DWORD)GetProcAddress(LoadLibrary("user32.dll"), "MessageBoxA");
	// 安装或者卸载HOOK
	if (!g_dwIATHookFlag){
		SetIATHook(pOldFuncAddr, (DWORD)MyMessageBox);
	}else{
		UnIATHook();
	}
	return 0;
}




BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	switch ( ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL,0,
            (LPTHREAD_START_ROUTINE)ThreadProc,
            NULL, 0,NULL);//创建新线程执行代码
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
	}
    return TRUE;
}
```

injection.cpp(运行来注入dll的程序):

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD GetPid(char* szName){
    HANDLE hprocessSnap = NULL;
    PROCESSENTRY32 pe32 = {0};
    hprocessSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0);//捕捉所有进程的快照
    if (hprocessSnap == INVALID_HANDLE_VALUE){
        //快照失败
        return 0;
    }
    //初始化pe32结构体
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hprocessSnap, &pe32)){
        do{
            if (!strcmp(szName, pe32.szExeFile)){
                printf("Process Found, PID: %d \n", (int)pe32.th32ProcessID);
                return (int)pe32.th32ProcessID;
            }
            //遍历查找进程名
        }while (Process32Next(hprocessSnap, &pe32));
    }else{
        CloseHandle(hprocessSnap);
    }
    return 0;
}



//远程线程注入
BOOL load_dll(DWORD dwProcessID, char* szDllPathName)
//进程PID和dll完整的路径
{
    BOOL bRet;
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwLength;
    DWORD dwLoadAddr;
    LPVOID lpAllocAddr;
    DWORD dwThreadID;
    HMODULE hModule;
    //获取进程句柄
    hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwProcessID);
    printf("%x \n", hProcess);
    if (hProcess == NULL)
    {
        OutputDebugString("fail to open process \n");
        return FALSE;
    }
    //把DLL文件路径字符串存入被注入进程的内存空间
    //计算dll路径名字长度，并且加上结尾0的空间
    dwLength = strlen(szDllPathName)+1;
    //远程申请内存空间
    lpAllocAddr = (LPVOID)VirtualAllocEx(hProcess,NULL,dwLength,MEM_COMMIT,PAGE_READWRITE);
    if (lpAllocAddr == NULL){
        OutputDebugString("VirtualAllocEx error \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    //拷贝dll路径名字到目标进程的内存
    bRet = WriteProcessMemory(hProcess, lpAllocAddr,szDllPathName,dwLength,NULL);
    if (bRet == NULL){
        OutputDebugString("bRet error \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    //获取kernel32.dll的地址
    hModule = GetModuleHandle("Kernel32.dll");
    if (!hModule)
    {
        OutputDebugString("GetModuleHandle error \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    //获取LoadLibraryA函数地址
    dwLoadAddr = (DWORD)GetProcAddress(hModule, "LoadLibraryA");
    if (!dwLoadAddr )
    {
        OutputDebugString("GetProcAddress error \n");
        CloseHandle(hProcess);
        CloseHandle(hModule);
        return FALSE;
    }
	
    //创建远程线程，加载dll
    hThread = CreateRemoteThread(hProcess, NULL, 0, (unsigned long (__stdcall *)(void *))dwLoadAddr, lpAllocAddr, 0, NULL);
    printf("%x \n", hThread);
    if (hThread == NULL)
    {
        OutputDebugString("fail to open RomoteThread \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    CloseHandle(hProcess);
	
    return TRUE;
}
void main(){
	load_dll(GetPid("1.exe"), "C:\\Users\\thinkpad\\Desktop\\IATHook\\dll\\1\\Debug\\1.dll");
}
```

被注入的程序：

```cpp
#include <windows.h>

int main(){
	while (1){
		MessageBox(0,0,0,0);
		Sleep(1000);
	}
	return 0;
}
```

#### INLINE HOOK

改函数代码的hook

IAT Hook的缺点：

1. 容易被检测到
2. 只能hook iat表里的函数

**INLINE HOOK的基本流程**：

1. 确定要改的那个函数的地址
2. 跳转到自定义的hook代码
3. 执行覆盖掉的代码部分
4. 跳转回去

**代码实现：**

暂时保留

#### Hook攻防

阶段1：

（防）检测jmp E9，检测跳转范围

（破）想方设法绕过

阶段2：

（防）写一个线程全代码校验/CRC校验【全代码校验的方式可以防止int3断点】

（破）修改检测函数、挂起检测线程

阶段3：

（防）先对相关api进行全代码校验，多个线程互相检测，并检测线程是否在活动中

（攻）使用瞬时钩子【重点建议自己操作一遍】/硬件钩子

## 硬编码

### 前缀指令(最大4byte/1byte each)

![image-20211109130305378](/img/image-20211109130305378.png)

前缀指令是可选的。

是根据内容本身去判断的。

分为4个组：

1. LOCK和REPEAT前缀指令

   LOCK     F0   (LOCK是用来锁地址总线的)

   REPNE/REPNZ       F2

   REP/REPZ              F3

2. 段前缀指令

   CS(2E), SS(36), DS(3E), ES(26), FS(64), GS(65)

3. 操作数宽度前缀指令

   66

4. 地址宽度前缀指令

   67

# 滴水中级班

## 保护模式

x86 CPU的3个模式：实模式、保护模式和虚拟8086模式

> 学习这段之前需要利用windbg配置一下内核调试的环境，有一点点麻烦。

保护模式有什么特点：

1. 段的机制
2. 页的机制

学习保护模式可以真正理解内核是如何运作的。

> 参考书籍：《intel白皮书第三卷》

### 段寄存器结构

段的机制非常复杂，想了解段机制要先了解段寄存器。

1. 什么是段寄存器？有哪些？

   当我们用汇编读写某一地址的时候：

   mov dword ptr ds:[0x123456],eax

   我们真正读写的地址是: ds.base + 0x123456

   段寄存器：ES CS SS DS FS GS LDTR TR **共8个**

2. 段寄存器的结构

   段寄存器有96bit，但是可见部分只有16位

   ```c
   struct SegMent{
       WORD Selector;   // 16位Selecter【可见部分】
       WORD Attributes; // 16bit属性 【表示可读可写可执行】
       DWORD Base;      // 32bit Base 【表示当前的段是从哪里开始的】
       DWORD Limit;     // 32bit  【表示当前段的整个长度是多少】
   }
   ```

   读段寄存器只能读16位，但是写段寄存器是写96位

### 段寄存器属性探测

如何证明不可见部分的存在呢？

Attribute除了CS段都是可读可写，CS段是可读可执行

Base只有FS段是0x7FFDE000,其他都是0

Limit除了FS是0xFFF其他都是0xFFFFFFFF

### 段描述符和段选择子

1. GDT（全局描述符表）LDT（局部描述符表*在windows中没有使用*）

   当我们执行类似mov DS, AX 指令的时候，CPU会查表，根据AX来查询。

   **gdtr寄存器(48bit)中存储了表的开始位置和它的长度**

   ```
   r gdtr     # 查看表的地址32bit
   r gdtl     # 查看表的长度16bit
   ```

2. 段描述符

   一个段描述符有8bytes

   ![段描述符](/img/段描述符.PNG)

   

3. 段选择子

   段选择子是一个16位的描述符

   该描述符指向了定义该段的段描述符

   ![段选择子](/img/段选择子.PNG)

4. 加载段描述符至段寄存器

   除了mov指令还有LES,LSS,LDS,LFS,LGS指令可以修改寄存器

   ```c
   char buffer[6];
   __asm{
       les ecx, fword ptr ds:[buffer] // 高两字节给es，低四字节给ecx
   }
   ```
   

### 段描述符的属性

#### P位 G位

P位位于高4bytes的第15个bit（index=15）G位index=23

P=1 段描述符有效 P=0 段描述符**无效**

G=0 Limit的单位是byte，界限是FFFFF

G=1 Limit的单位是4kB，就是Limit+FFF 

#### S位 TYPE域

S=1 代码段或者数据段描述符

S=0 系统段描述符

**流程：先看S位，确定是系统段描述符还是代码/数据段描述符，再判断是数据还是代码，最后根据TYPE域判断最终的属性。**

![image-20211005151904849](/img/image-20211005151904849.png)

![image-20211005152028907](/img/image-20211005152028907.png)

![image-20211005152145908](/img/image-20211005152145908.png)

![image-20211005152252713](/img/image-20211005152252713.png)

#### DB位

高4bytes中index=22

1. 对CS段的影响

   D=1采用32位寻址方式

   D=0采用16位寻址方式

   前缀67 改变寻址方式

2. 对SS段的影响

   D=1 隐式堆栈访问指令（PUSH POP CALL）使用32位ESP

   D=0 隐式堆栈访问指令使用16位堆栈指针寄存器SP

3. 向下拓展的数据段

   D=1 段上限为**4GB**

   D=0 段上限为**64kB**
   
   *向下拓展就是XS.Base+XS.Limit以外的范围*

### 段权限检查

#### CPU分级

权限大小：

ring0(系统)>ring1>ring2>ring3(应用程序)

#### 如何查看当前程序处于哪一环

看CS寄存器的段选择子，CS段/SS段选择子的后两位称为当前的特权级别，叫CPL(Current Privilege Level当前特权级)。

#### DPL

<u>描述符的特权级别</u>

是存储在段描述符中的，规定了访问该段所需要的的特权级别是什么。

例：

```
mov DS,AX
如果AX指向的段DPL=0，但当前程序的CPL=3这行指令是执行不成功的。
```

#### RPL(Request Privilege Level)请求特权级别

RPL是针对段选择子而言的，每个段的选择子都有自己的RPL(上面的图里面有)

#### "数据段"的权限检查

检查CPL<=DPL && RPL <= DPL

#### 小结

CPL: CPU当前的权限级别

DPL: 如果你想访问我，你应该具备什么样的权限

RPL: 用什么权限去访问一个段



### 代码跨段

本质就是修改CS段寄存器，CS与eip会同时修改（CS不能通过MOV,LES等指令进行修改）

#### 代码跳转

> 只改变EIP的指令：JMP/CALL/JCC/RET

**同时**修改CS与EIP的指令:

**JMP FAR**/ CALL FAR/ RETF / INT / IRETED

* JMP 0x20:0x004183D7   ; JMP FAR

  长跳转

  1. 先拆分段选择子。

     0x20 -> 0000 0000 0010 0000

     最低2位是RPL = 00

     倒数第三位是TI = 0

     剩下的值是索引的值INDEX=4
  
  2. 查表得到段描述符
  
     因为TI为0所以查GDT表
  
     INDEX=4找到相应的段描述符
  
     四种情况可以跳转：**代码段**、调用门、TSS任务段、任务门（后三种属于系统段描述符）。
  
  3. 权限检查
  
     如果是非一致代码段**(需要高权限)**，要求：CPL==DPL且RPL<=DPL
  
     如果是一致代码段**（共享段）**，要求CPL>=DPL
  
  然后CPU加载段描述符到CS段寄存器中。
  
  最后CPU将CS.Base+Offset的值写入EIP然后执行CS:EIP处的代码，段间跳转结束。 

### 长调用与短调用

长调用call far

指令格式：CALL CS:EIP(EIP是废弃的)

CS必须要是一个调用门

对应RETF长返回

![image-20211114110040837](/img/image-20211114110040837.png)

![image-20211114110128658](/img/image-20211114110128658.png)

总结：
* 跨段调用的时候，一旦有权限切换，就会切换堆栈。
* CS的权限一旦改变，SS的权限也要随着改变，CS和SS的登记必须一样
* JMP FAR只能跳转到同级的非一致代码段，**但是CALL FAR可以通过调用门提权**，提升CPL的权限。
* *SS与ESP从哪里来？参见TSS段*

### 调用门

> windows里面没有使用调用门

#### 执行流程

**指令格式CALL CS:EIP(EIP是废弃的)**

1. 根据CS的值查GDT表，找到对应的段描述符，**这个描述符是一个调用门**
2. 在调用门描述符中存储**另一个代码段的段选择子**
3. 选择子指向的段，段.Base+偏移地址就是真正要执行的地址

![image-20220112145117192](/img/image-20220112145117192.png)

> 调用门最大的作用是提权 

![image-20220112162314440](/img/image-20220112162314440.png)

### 中断门

> windows使用了中断门
>
> 1. 系统调用
> 2. 调试

中断门是查询IDT表，由一系列描述符组成，每个8bytes

在windbg中查看IDT表的基址和长度：

```
r idtr           # 基址
r idtl           # 长度
```

IDT表中包含三种门描述符：

1. 任务门描述符
2. **中断门描述符**
3. 陷阱门描述符

![image-20220112162956896](/img/image-20220112162956896.png)

### 陷阱门

> 和中断门几乎一样

![image-20220112163230378](/img/image-20220112163230378.png)

**中断门和陷阱门的区别：中断门执行时会将IF位清零，但陷阱门不会。**

IF如果为0，就不再接受可屏蔽中断。

###  任务段

TSS(Task-state segment)，任务状态段。

TSS是一块内存，有104个字节。

![image-20220117220617200](/img/image-20220117220617200.png)

![image-20220117220808131](/img/image-20220117220808131.png)

TSS允许我们替换所有寄存器。

**CPU如何找到TSS？通过TR段寄存器**

![image-20220117220949283](/img/image-20220117220949283.png)

![image-20220117221036873](/img/image-20220117221036873.png)

是系统段描述符的一种。

#### TR段寄存器的读写

1. 写：LTR

   使用LTR指令，只改变TR寄存器的值(96bit)，并没有真正的改变TSS。

   只能在系统层使用。

   加载后TSS段描述符的状态位会发生改变。

2. 读：STR

   只能读到选择子。

![image-20220117222740079](/img/image-20220117222740079.png)

### 任务门

思考题：既然已经可以访问任务段了，为什么还要有任务门呢？

![image-20220117223557732](/img/image-20220117223557732.png)

![image-20220117223712568](/img/image-20220117223712568.png)

### 分页







## 系统调用

### API函数的调用过程

大部分的api函数都是在ring0实现的

练习：自己编写WriteProcessMemory函数(不是用任何dll，直接调用ring0函数)，并在代码中使用。

**重写api的意义：自己实现api，可以避免3环恶意hook**

### ring3进ring0

#### _KUSER_SHARED_DATA结构体

![image-20211109132844715](/img/image-20211109132844715.png)

> _KUSER_SHARED_DATA结构体内容如下：
>
> ![image-20240106161614860](/img/image-20240106161614860.png)
>
> 注意到0x300的位置上是SystemCall 4Bytes,这个地方其实存的就是系统调用函数的地址。



![image-20211109133039825](/img/image-20211109133039825.png)

> 0x7FFE0300中存储的是什么？就是上面的SystemCall函数的地址。

![image-20211109133232378](/img/image-20211109133232378.png)

> 何如判定，使用到cpuid指令：
>
> cpuid指令的参数通过eax传递。
>
> eax=1时，返回值在ecx&edx中。



#### 进ring0需要修改哪些寄存器

1. CS要变
2. SS要和CS一起变
3. 堆栈变化，需要新的ESP
4. 代码位置需要变，需要新的EIP

上面的两个函数就是用来进ring0的。

`ntdll!KiIntSystemCall()`是通过**中断门**进入内核的：

![image-20211109133615546](/img/image-20211109133615546.png)

`ntdll!KiFastSystemCall()`函数是通过快速调用进ring0的：

![image-20211109133705689](/img/image-20211109133705689.png)

1. INT 0x2E进0环

   步骤1：在IDT表中找到0x2E号门描述符

   步骤2：分析CS/SS/ESP/EIP的来源

   步骤3：分析EIP是什么

接下来会进入到nt!KiSystemService函数中，这里已经是内核模块。

2. sysenter指令进r0

   需要的寄存器值保存在MSR寄存器中。

接下来会执行的函数是nt!KiFastCallEntry()；

内核模块：ntoskrnl.exe/ntkrnlpa.exe

### API调用的保存现场

TODO



## 进程与线程

### 进程结构体EPROCESS(r0)

```
kd> dt _EPROCESS
第一个成员是pcb KPROCESS结构体
```

![image-20240106165333768](/img/image-20240106165333768.png)

KPROCESS结构体中最重要的是第三个成员，是页表基址。

![image-20240106170228537](/img/image-20240106170228537.png)

![image-20240106170330157](/img/image-20240106170330157.png)

![image-20240106170646260](/img/image-20240106170646260.png)

![image-20240106170927494](/img/image-20240106170927494.png)

0x1b0 PEB



TODO



## 驱动开发

### 开发环境配置

#### 安装WDK

现在官网是自动安装的，还会配置好和VS2022的插件。

#### 第一个驱动程序

可以参考：[编写 Hello World Windows 驱动程序 (KMDF) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/gettingstarted/writing-a-very-small-kmdf--driver)

在vs2022中创建KMDF,empty即可

用.c文件编写代码。

```c
#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    (DriverObject);
    // 这里使用DbgPrintEx输出才能被调试器接收并显示
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "驱动运行~\r\n");  
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
){
    (RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "驱动运行~\r\n");
    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
```

> 流程：代码->生成.sys->部署->运行->停止->卸载

DriverEntry(); 入口函数

DriverUnload(); 回调

DbgPrint();   输出

> 部署驱动程序:
>
> 使用驱动管理.exe + DebugView(监视核心)
>
> 

### 驱动调试

可以用来双机调试的工具：virtualkd

#### 符号

> File -> Symbol File Path (control+S)
>
> ![image-20240112191242007](/img/image-20240112191242007.png)

复制编译好的符号路径然后.reload：

![image-20240112191538211](/img/image-20240112191538211.png)

#### 断点

```c
_asm{
    int 3;
}
```

### 内核编程基础

只能用r0的api。

```
#include <ntddk.h>
```

遇到问题查WDK文档。

如果要使用未导出函数则需要自己定义，通过特征码搜索或者解析内核PDB。

```c
返回值：NTSTATUS
```

![image-20240112192550625](/img/image-20240112192550625.png)

#### 使用异常处理

![image-20240112192810672](/img/image-20240112192810672.png)

```c
__try{
    
}__except(filter_value){
    ...
}
```

#### 内核内存函数

![image-20240112192929376](/img/image-20240112192929376.png)

#### 内核字符串

除了CHAR/WCHAR(wchar_t)，还有ANSI_STRING/UNICODE_STRING

![image-20240112193629160](/img/image-20240112193629160.png)

![image-20240112193702441](/img/image-20240112193702441.png)

### 内核空间与内核模块

通过DRIVER_OBJECT->DriverSection(指向双向链表)可以遍历内核模块。

这个和PEB.ldr中的双向链表几乎一致。

### r0与r3通信（常规方式）

#### 设备对象

内核模块接收消息只能通过设备对象来进行。

IRP(I/O Request Package)

![image-20240112213820889](/img/image-20240112213820889.png)

#### 创建设备对象

```c
// 创建设备对象名称，这个名字是给r0看的，要挂到树上
UNICODE_STRING Devicename;
RtlInitUnicodeString(&Devicename, L"\\Device\\MyDevice");
// 创建设备
IoCreateDevice(
    pDriver,    // 当前设备属于哪个驱动对象
    0,
    &Devicename,    // 设备对象的名称
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &pDeviceObj         // [out]设备对象指针
);
```

#### 设置交互数据方式

```c
pDeviceObj->Flags |= DO_BUFFERED_IO;  // 缓冲区方式读写
// DO_DIRECT_IO       // 直接方式读写
```

#### 创建符号链接名称

```c
#define SYMBOLICLINK_NAME L"\\??\\MyTestDriver"
     // r3中为"\\\\.\\MyTestDriver"
RtlInitUnicodeString(&SymbolicLinkName, SYMBOLICLINK_NAME);
```

#### 创建符号链接

本质上是起别名给r3用。

#### IRP与派遣函数

![image-20240512141734621](/img/image-20240512141734621.png)

#### IRP的类型

![image-20240512142020003](/img/image-20240512142020003.png)

![image-20240512142140926](/img/image-20240512142140926.png)

用的最多最灵活的是IRP_MJ_DEVICE_CONTROL，是应用层调用deviceControl函数产生的。

![image-20240512142428605](/img/image-20240512142428605.png)

MajorFunction里面存储的是派遣函数。

完整IRP通信驱动代码：

```c
#include <ntddk.h>
#include <stdio.h>
#include <stdlib.h>

// 0-2047是保留的，可以用2048-4095
#define OPER1 CTL_CODE(FILE_DEVICE_UNKNOWN, 3001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER2 CTL_CODE(FILE_DEVICE_UNKNOWN, 3002, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT g_pDeviceObj = NULL;
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    (DriverObject);
    
    // 删除符号链接
    UNICODE_STRING SymbolicLinkName;
    RtlInitUnicodeString(&SymbolicLinkName, L"\\??\\MyTestDriver");
    IoDeleteSymbolicLink(&SymbolicLinkName);
    // 删除设备
    IoDeleteDevice(g_pDeviceObj);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DriverUnload~\r\n");
    
}

NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevice, PIRP pIrp) {
    (pDevice);
    // 处理自己的业务
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[info] IrpCreateProc~\r\n");
    // 设置返回状态
    pIrp->IoStatus.Status = STATUS_SUCCESS;   // getlasterror()
    pIrp->IoStatus.Information = 0;            // 返回给r3多少数据
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevice, PIRP pIrp) {
    (pDevice);
    // 处理自己的业务
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[info] IrpCloseProc~\r\n");
    // 设置返回状态
    pIrp->IoStatus.Status = STATUS_SUCCESS;   // getlasterror()
    pIrp->IoStatus.Information = 0;            // 返回给r3多少数据
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IrpDeviceProc(PDEVICE_OBJECT pDevice, PIRP pIrp) {
    (pDevice);
    // 处理自己的业务
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[info] IrpDeviceProc~\r\n");
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION pIrpStack;
    ULONG uIoControlCode;
    PVOID pIoBuffer;
    ULONG uInLength;
    ULONG uOutLength;
    
    // 初始化输入输出缓冲区
    UCHAR ReadBuf[1024] = { 0 };
    UCHAR WriteBuf[] = "hello Mz1! ";

    // 获取IRP数据
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    // 获取控制码
    uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    // 获取缓冲区地址（输入和输出缓冲区都是一个）
    pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
    // r3 发送数据的长度
    uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    // r0 发送数据的长度
    uOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    // 根据操作码决定操作
    switch (uIoControlCode) {
    case OPER1:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[info] OPER1\r\n");
        // 接收&输出数据
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "       接收字节数: %d \r\n", uInLength);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "       输出字节数: %d \r\n", uOutLength);
        // read
        memcpy(ReadBuf, pIoBuffer, uInLength);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "       recv: %s \r\n", ReadBuf);
        // write
        memcpy(pIoBuffer, WriteBuf, sizeof(WriteBuf));
        // set status
        pIrp->IoStatus.Information = sizeof(WriteBuf);
        status = STATUS_SUCCESS;
        break;
    case OPER2:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[info] OPER2\r\n");
        pIrp->IoStatus.Information = 0;
        status = STATUS_SUCCESS;
        break;
    }




    // 设置返回状态
    pIrp->IoStatus.Status = status;   // getlasterror()
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
){
    (RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DriverEntry~\r\n");
    DriverObject->DriverUnload = DriverUnload;

    PDEVICE_OBJECT pDeviceObj = NULL;
    // 创建设备对象名称，这个名字是给r0看的，要挂到树上
    UNICODE_STRING Devicename;
    RtlInitUnicodeString(&Devicename, L"\\Device\\MyDevice");

    // 创建设备
    NTSTATUS status = IoCreateDevice(
        DriverObject,    // 当前设备属于哪个驱动对象
        0,
        &Devicename,    // 设备对象的名称
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pDeviceObj         // [out]设备对象指针
    );
    if (status != STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[err] IoCreateDevice~\r\n");
        return status;
    }
    g_pDeviceObj = pDeviceObj;    // 复制一份全局对象
    // 设置交互数据方式
    pDeviceObj->Flags |= DO_BUFFERED_IO;
    // 创建符号链接名称
    UNICODE_STRING SymbolicLinkName;
    // r3: CreateFile "\\\\.\\MyTestDriver"
    RtlInitUnicodeString(&SymbolicLinkName, L"\\??\\MyTestDriver");
    // 创建符号链接
    status = IoCreateSymbolicLink(&SymbolicLinkName, &Devicename);
    if (status != STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[err] IoCreateSymbolicLink~\r\n");
        return status;
    }
    // 设置派遣函数
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateProc;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCloseProc;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceProc;
    
    return STATUS_SUCCESS;
}
```

对应的r3测试代码：

```c
// r3proj.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <winioctl.h>

// 0-2047是保留的，可以用2048-4095
#define OPER1 CTL_CODE(FILE_DEVICE_UNKNOWN, 3001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER2 CTL_CODE(FILE_DEVICE_UNKNOWN, 3002, METHOD_BUFFERED, FILE_ANY_ACCESS)

HANDLE g_hDevice;

DWORD IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen) {
    DWORD dw = 0;
    // 设备句柄/操作码/输入缓冲区地址/长度/输出缓冲区地址/输出缓冲区长度/返回长度/指向OVERLAPPED此处为NULL
    DeviceIoControl(g_hDevice, dwIoCode, InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL);
    return dw;
}



int main()
{
    // 打开Device
    // \\\\.\\MyTestDriver
    g_hDevice = CreateFile(L"\\\\.\\MyTestDriver", GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    DWORD err = GetLastError();
    printf("err: %d \n", err);
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        printf("CreateFile ok \n");
    }
    else {
        printf("error \n");
        return -1;
    }
    // 测试通信
    UCHAR InBuffer[1024] = "hihihihihihihihihihihihiashdasda";
    UCHAR OutBuffer[1024] = { 0 };
    DWORD ret = IoControl(OPER1, InBuffer,  sizeof(InBuffer), OutBuffer, sizeof(OutBuffer));
    
    
    printf("r3 recv[%d]: `%s` \n", ret, OutBuffer);
    CloseHandle(g_hDevice);

    printf("Over ok \n");
    return 0;
}
```









### SSTD hook

SystemServiceTable

通过线程结构体找到这个表

```
> dd KeServiceDescriptorTable    # SSDT
```

![image-20240516142126243](/img/image-20240516142126243.png)

![image-20240516143314152](/img/image-20240516143314152.png)

![image-20240516143406558](/img/image-20240516143406558.png)



## 内存管理

内核中是通过链表将空闲空间穿起来管理的。

### 用户空间的地址管理

搜索二叉树

找进程_EPROCESS中的Vad_Root(在我这个系统中位于0x7d8的位置)，这个就是搜索二叉树的根。

```
1: kd> dt _EPROCESS ffff8105498dc080
nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : 0x00000000`00000c40 Void
	...
   +0x7d0 ModifiedPageCount : 7
   +0x7d4 ExitStatus       : 0n259
   +0x7d8 VadRoot          : _RTL_AVL_TREE
   +0x7e0 VadHint          : 0xffff8105`472cbe60 Void
   +0x7e8 VadCount         : 0x60
   +0x7f0 VadPhysicalPages : 0
   +0x7f8 VadPhysicalPagesLimit : 0
...

```

该节点的类型是\_MMVAD(x86)，但是实际我在x64操作的时候似乎是_RTL_BALANCE_NODE

```
1: kd> dt _MMVAD
nt!_MMVAD
   +0x000 Core             : _MMVAD_SHORT
   +0x040 u2               : <anonymous-tag>
   +0x048 Subsection       : Ptr64 _SUBSECTION
   +0x050 FirstPrototypePte : Ptr64 _MMPTE
   +0x058 LastContiguousPte : Ptr64 _MMPTE
   +0x060 ViewLinks        : _LIST_ENTRY
   +0x070 VadsProcess      : Ptr64 _EPROCESS
   +0x078 u4               : <anonymous-tag>
   +0x080 FileObject       : Ptr64 _FILE_OBJECT
```

```
1: kd> dt _RTL_BALANCED_NODE 0xffff810549945ce0
nt!_RTL_BALANCED_NODE
   +0x000 Children         : [2] 0xffff8105`472cb690 _RTL_BALANCED_NODE
   +0x000 Left             : 0xffff8105`472cb690 _RTL_BALANCED_NODE
   +0x008 Right            : 0xffff8105`49947400 _RTL_BALANCED_NODE
   +0x010 Red              : 0y1
   +0x010 Balance          : 0y01
   +0x010 ParentValue      : 1

```









# Windbg指令

```bash
g            # 继续执行
u <addr>     # 反汇编某地址/函数
dt xxx       # 查看某种数据结构
.reload       # 重新加载调试符号
!process 0 0   # 查看所有进程
.process xxxxxx # 进入进程对应的内核空间

```









# CSAPP

## ELF文件结构

![elf文件结构](/img/elf文件结构.png)



## 7 链接

### ELF文件格式

下图为典型的elf文件格式：

![image-20211112125527894](/img/image-20211112125527894.png)

> 就很神奇，pe的节表是在头部，但是elf的是在尾部

```
.text: 已编译程序的机器代码
.rodata: 只读数据，比如printf语句中的格式串和开关语句的跳转表
.data: 已初始化的全局和静态C变量
.bss: 未初始化的全局和静态C变量 and 所有被初始化为0的全局或静态变量
.symtab: 一个符号表，存放在程序中定义和引用的函数和全局变量的信息。
		每一个可重定位目标文件在.symtab中都有一张符号表(除非被人为去除)
.rel.text: 一个.text节中位置的列表(类似于pe中的重定位表?)，书上说可执行目标文件中并不需要重定位信息因此通常省略。
.debug: 一个调试符号表，-g选项条用编译器驱动程序的时候才会得到这张表。
.line: 原始C源代码中行号和.text节中机器指令之间的映射。(同样需要-g)
.strtab: 一个字符串表，其内容包括.symtab和.debug节中的符号表，以及节头部中的节名字。字符串表就是以null结尾的字符串的序列
```

### 静态链接库

静态库(libc.a)存档(archive)

其实就是打包了一系列目标模块(.o)的合集，这样用啥就把啥搬进来就行了。

### 可执行目标文件

![image-20211112164254878](/img/image-20211112164254878.png)

大体上分为数据段和代码段。

和pe一样，权限是由段头部表来进行说明的(大概吧)。

### 动态链接库

```bash
gcc -shared -fpic -o libvector.so addvec.c multvec.c   # 生成动态链接库
gcc -o proc main.c ./libvector.so             # 使用动态链接库(编译时使用)
```

还有动态调用的方式：

```cpp
#include <dlfcn.h>
void* dlopen(const char* filename, int flag);   // 如果成功但会句柄指针，出错返回NULL
void* dlsym(void* handle, char* symbol);   // handle就是上个函数的返回值, 如果成功就返回符号指针。
int dlclose(void* handle);    // 关闭句柄
const char* dlerror();    // 返回错误消息，类似于GetLastError
```

#### GOT表&PLT表

> 可以参考：https://blog.csdn.net/weixin_43847969/article/details/104921964

Global Offset Table 全局偏移量表，常和PLT表(Procedure Linkage Table)结合使用

有一个小概念叫PIC(Position-Independent Code位置无关代码)

因为数据段和代码段之间的距离是不变的，所以通过got表去引用全局变量。

#### 库打桩机制

> 感觉就像是iat hook？

其实就是更改符号的引用。

比较好用的是**运行时打桩**。

可以对任何库函数进行打桩。





## 8 异常控制流

### fork函数

pid_t fork(void);    // pid_t 是一个宏定义 本质是int

头文件：

```c
#include<unistd.h>
#include<sys/types.h>
```

可以用来区分是父进程还是子进程。

#### waitpid

```c
pid_t waitpid(pid_t pid, int* statusp, int options);
```

用于等待它的子进程终止或者停止。

简单的版本是**wait(int* status)**,等价于waitpid(-1, &status, 0);

### 加载并运行程序

#### execve函数

执行一个新的程序，需要通过信号来回收。

## 9 虚拟内存

MMU（Memory Management Unit）内存管理单元（cpu上的专用硬件），利用放在主存中的查询表（**页表pagetable**）来**动态翻译虚拟地址**，这个表的内容由操作系统管理。

<u>简单地说，虚拟内存就是拿磁盘当内存使用的一种方式，涉及缺页异常处理。</u>

在linux操作系统中，内核为每个进程维护一个单独的任务结构（源码中task_struct），mm指向mm_struct，它描述了虚拟内存的当前状态。其中pgd指向第一级页表的基质，mmap指向一个vm_area_struct的链表。每当内核运行这个进程时，就将pgd放在CR3控制寄存器中。

### 内存映射

* 映射普通文件
* 映射匿名文件，又称请求二进制零的页

*私有对象的写拷贝*

#### 再看fork函数

就是利用了写拷贝的方式进行的。

#### 再看execve

基本执行步骤（等于就是换了个程序执行吧）：

1. 删除已经存在的用户区域
2. 映射私有区域
3. 映射共享区域
4. 设置程序计数器PC

#### mmap函数（用户级内存映射）

munmap函数删除虚拟内存区域

#### 动态内存分配（heap）

##### malloc&free

```c
#include<stdlib.h>
void* malloc(size_t size);  // 若成功返回分配块的指针，若错误则为NULL
// 分配的大小考虑字节对齐
// 类似函数calloc realloc
void free(void* ptr);
```



