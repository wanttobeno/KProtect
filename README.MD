
##### 说明

补充的缺失的代码。丢在硬盘都遗忘了，上传备份下。

仅供学习，不保证效果。


##### 资源来源说明

来自 [某总$KProtect 价值3000元的公司级反调试产品 还原复现开源](https://bbs.pediy.com/thread-250468.htm)

#### 驱动保护功能说明

##### 0x01 隐藏进程
原理没什么多说的，基本就是 @xiaofu 所分析的
将 EPROCESS->InheritedFromUniqueProcessId 置为 System 
将 EPROCESS->UniqueProcessId 置为 winlogon.exe（其他系统进程皆可）
通过动态获取 InheritedFromUniqueProcessId 和 UniqueProcessId 偏移 提高兼容性
值得注意的是，此方法会在 低版本 Win7系统 任务管理器 出现 Bug
现象是 winlogon 的进程会疯狂增加 且增加的进程 Pid 为 -1
（仅仅只是任务管理器表项增加 实际进程只有一个）
在高版本 Win7 和 Win10 没有此现象

##### 0x02 回调保护
通过 ObRegisterCallbacks 注册 Process 和 Thread 回调

当目标进程为被保护进程时，进行降权处理

在使用了隐藏进程后，回调貌似并没有什么作用

在 CheatEngine 通过进程名所找到的 Demo 实为 winlogon.exe 的进程

所访问的内存也是属于 winlogon.exe 进程

所以回调的作用也仅仅在隐藏进程被攻破后才有作用



##### 0x03 全局调试权限 调试端口 清零
通过 NtCreateDebugObject 函数地址 往后遍历特征码 计算得出 DbgkDebugObjectType 的指针
然后通过结构体 对 ValidAccessMask 标识置 0
如果要防止被还原，可在线程中循环对此标识置 0 或监控，再对线程做 crc

动态取出 DebugPort 的偏移 在用线程循环判断是否有值

##### 0x04 HOOK DBG API
Hook DbgUiRemoteBreakin

Hook DbgBreakPoint
这里学习某眼睛的操作，比某总多 Hook 了一个 DbgBreakPoint

将 DbgUiRemoteBreakin Jmp到 LdrShutdownProcess 实现调用此 Api 程序直接退出

而 DbgBreakPoint 则直接对其 int3 写 ret 即可



##### 0x05 检查标识位
调用 ZwQuerySystemInformation
检查 SystemKernelDebuggerInformation 中的 KernelDebuggerEnabled 是否为 true
检查 SystemKernelDebuggerInformation 中的 KernelDebuggerNotPresent 是否为 false
调用 ZwQueryInformationProcess

检查 ProcessDebugPort 是否有值

检查 ProcessDebugObjectHandle 是否有值

检查 ProcessDebugFlags 是否为 0

取得 PEB 指针

检查 BeingDebugged 是否为 1

扫描 Ldr 指向的内存是否填充 0xFEEEFEEE

检查 ProcessHeap->Flags 标识

检查 NtGlobalFlag 标识

附件项目里的只是通过 __readfsdword 取得的 Peb 指针
仅支持在 x86 编译环境下使用，x64 的自己想办法
标志位只是简单输出了一下 请自行写判断
（算是留的 2 个小坑 防止伸手党） 

##### 0x06 断下崩溃
调用 ZwSetInformationThread 对 ThreadHideFromDebugger 置 NULL 使线程对调试器隐藏 阻止调试事件发往调试器
参数一为线程句柄，由于附件中的 Demo 是直接创建的线程来循环操作的
如果直接 GetCurrentThread() 调用一次，则在主线程内断下不会崩溃
所以通过线程参数，将主线程句柄也传递过来调用 2 次

##### 0x07 疯狂抛异常
异常肯定还有更好用的，不过try肯定是最简单的


#### 其他

[新版xxprotect保护调试以及其x64隐藏进程等原理](https://bbs.pediy.com/thread-250404.htm)


[如何调试xxProtect](https://bbs.pediy.com/thread-248918.htm)




