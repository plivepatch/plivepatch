热补丁技术实践
=============
# 测试环境
## Linux 4.13.0-41-generic #46~16.04.1-Ubuntu SMP Thu May 3 10:06:43 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

# 步骤：
## 1.下载代码;
## 2.编译代码 make;
## 3.拷贝libfunc.so 至 /usr/lib/目录下：sudo cp libfunc.so /usr/lib/
## 4.运行 main：./main
## 5.运行 plivepatch pid libsopath oldfunction newfunction 完成函数替换。
