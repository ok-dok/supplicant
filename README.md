# 安朗（小蝴蝶）拨号认证客户端Java版
## 支持院校
#### 测试通过
1. 烟台大学赛尔网
2. 广州大学华软软件学院

## 运行环境
- Windows 7/8/10
- Linux
- Mac OS

## 重要提示
`仅支持` 外网认证（BAS认证）
`不支持` PPPOE、Web认证

## 使用说明
1. 需要依赖java运行环境，jre或jdk1.7版本以上，同时配置环境变量，windows系统可直接安装exe安装包，无需手动配置环境变量，Linux或Mac请下载jdk，并配置环境变量，百度上教程很多，不会的就百度吧。这里附上jre下载地址：http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html<br>

2. 直接使用编译文件，bin/Supplicant.class文件，复制到任意目录中，打开命令行，进入到该目录。请使用 -u <用户名> -p <密码> 参数指定用户名密码，命令如下：
 ```
 java Supplicant -u 用户名 -p 密码
 ```
3. 自行编译，src/Supplicant.java文件，复制到任意目录中，打开命令行工具，进入该目录，执行 
 ```
 javac Supplicant.java 
 ```
　进行编译，会生成 Supplicant.class文件，然后按照2.所述进行操作。<br>

4. Ctrl + C 退出程序，一段时间没有呼吸请求会自动下线

注意：自动获取本地网卡信息会读取电脑有线网卡的mac、ip，拨号认证前，请将网卡设置为自动获取（适用于dhcp自动获取）,如果校园网不支持dhcp，请自行修改网卡ip地址、网关等信息。<br>

## Bug Report
Email: shawn_hou@163.com<br>
Email: 842328916@qq.com