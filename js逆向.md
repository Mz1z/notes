# JS逆向

参考

> https://www.bilibili.com/video/BV1XR4y147fQ?p=91

## 工具

### f12调试器下断点

### 发条js调试工具

### PyExecJs

实现使用python执行js代码

#### 环境安装

1. 需要node

2. pip install PyExecJS

3. 使用

   ```python
   import execjs
   # 1. 实例化一个node对象
   node = execjs.get()
   # 2. js源文件加载
   ctx = node.compile(open('xxx.js', encoding='utf-8').read()) # 或者直接用字符串
   # 3. 执行js函数
   funcName = 'getPwd("123456")'
   pwd = ctx.eval(funcName)   # 执行js函数
   ```

   

