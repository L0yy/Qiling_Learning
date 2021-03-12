https://github.com/qilingframework/qiling



重要是看重他的沙箱效果

先了解一下他的结构

分解析构，先分析Windwos平台的仿真



Setup.py文件

首先是这个库需要的依赖

```
capstone>=4.0.1    #处理传入的汇编，转换成字节码，传入unicorn仿真
unicorn>=1.0.2     #用于指令仿真qiling的核心
pefile>=2019.4.18  #解析PE文件结构
python-registry>=1.3.1
keystone-engine>=0.9.2
pyelftools>=0.26
gevent>=20.9.0
```

整个代码库的代码都在qiling目录下，其他目录都是演示或说明



先看一段用qiling作者模拟win32程序的例子

```python
from qiling import *

def test_pe_win_x86_NtQueryInformationSystem(self):
    ql = Qiling(
        ["../examples/rootfs/x86_windows/bin/NtQuerySystemInformation.exe"],
        "../examples/rootfs/x86_windows")
    ql.run()
    del ql
```

很简单，实例化Qiling类，然后调用他的run方法



qinling/core.py

要注意这个类的实现

`class Qiling(QlCoreHooks, QlCoreStructs): ` 

继承了QlCoreHooks和QlCoreHooks，可以先大致看一下这两个类的函数

```python
class A():
    def __init__(self):
        self.Name = "A Func"
        print(self.Name)

class B():
    def __init__(self):
        self.Name = "B Func"

    def GetB(self):
        print(self.Name)

class  C(A,B):
    def __init__(self):
        self.Name = "C Func"
        print("A Init")

c = C()
c.GetB()
==============输出================
A Init
C Func
```


qiling/loader 用于加载各种类型的文件，本文分析windwos程序加载


分析到：Core.py:174 睡觉！






pe.OPTIONAL_HEADER.SizeOfStackReserve   Stack Size


GS + 0x30 = PTEB
GS + 0x60 = PPEB







