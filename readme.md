PE1 通过读取文件，来分析文件的DOS头文件，PE头文件以及PE可选头文件，同时PE可选头文件在32位跟64位系统下输出是有区别的。
PE2 新增对Section的数据读取
PE3 模拟文件从硬盘被读取到内存再恢复到硬盘的过程（32位文件）
PE4 先通过bp MessageBoxA找到该函数地址，然后修改OEP先调用messageboxA,跳转后再调用notepad
PE5 PE6写反了
PE6 新增一个节
PE5 在新增的节上进行代码注入

