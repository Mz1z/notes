---
typora-copy-images-to: img
typora-root-url: ./
---

# 开发/基础

## adb

位置在android_sdk/platform-tools/中

### 一些基本命令

```bash
adb devices [-l]   # 查看连接设备
adb kill-server      # 关掉服务器
adb install path_to_apk   # 安装apk

# 端口转发
adb forward tcp:6100 tcp:7100   # 设置了主机端口 6100 到设备端口 7100 的转发

# 文件传输
adb pull remote local
adb push local remote

# 打开shell
adb shell

# 获取运行的app的信息
adb shell dumpsys activity top
```

## UI

可以用xml定义，也可以用代码定义。

`View `类表示通用的` View `对象。Android中的常用控件最终会扩展`View `类。

`ViewGroup `是一个视图，它包含其他视图。` ViewGroup `是布局类列表的基类。

### 通用布局属性

每个` View `和` ViewGroup `都有一组通用属性。

- layout_width指定View或ViewGroup的宽度
- layout_height指定View或ViewGroup的高度
- layout_marginTop指定View或ViewGroup顶部的额外空间
- layout_marginBottom指定View或ViewGroup底部的额外空间
- layout_marginLeft指定View或ViewGroup左侧的额外空间
- layout_marginRight指定View或ViewGroup右侧的额外空间
- layout_gravity指定子视图的位置
- layout_weight指定布局中应分配给View的额外空间量
- layout_x指定View或ViewGroup的x坐标
- layout_y指定View或ViewGroup的y坐标

## NDK



## Service

服务是一个后台运行的组件.

![image-20211114111836748](/img/image-20211114111836748.png)

## BroadcastReceiver

广播接收者

可以静态注册，可以动态注册。

## Content Resolver

内容提供者





# 逆向

