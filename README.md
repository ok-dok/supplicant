# supplicant 
## 安朗（小蝴蝶）拨号认证客户端Java版
### 使用说明：<br>
1. 直接使用编译文件，bin/Supplicant.class文件，复制到任意目录中，打开命令行，进入到该目录。<br>
　初次使用请执行 
 ```
 java Supplicant -u 用户名 -p 密码
 ```
　进行拨号认证。以后直接控制台命令执行 
 ```
 java Supplicant 
 ```
 即可进行拨号认证。<br>
2. 自行编译，src/Supplicant.java文件，复制到任意目录中，打开命令行工具，进入该目录，<br>
　执行 
 ```
 javac Supplicant.java 
 ```
 进行编译，会生成 Supplicant.class文件，然后按照方式1进行操作。<br>
 3. 使用-c参数可指定配置文件，但默认读取当前目录下的config.properties配置文件，如
 ```
 java Supplicant -c config.propties
 ```
### 配置说明
初次成功运行连接认证网络后，会在目录下生成config.properties配置文件，配置文件以utf-8编码，配置信息如下所示：<br>
- dhcp=0　　　　//dhcp配置，默认为0，无需改动
- server_ip=219.218.154.250　　　//服务器ip地址（自动获取）
- username=201358501113　　　　　//用户名
- service=internet　　　　　　　//internet服务（自动获取）
- client_version=3.8.2　　　　　//小蝴蝶认证版本（默认3.8.2）
- local_ip=180.201.54.232　　　//本地ip地址（初次运行自动获取，适用于dhcp自动获取ip地址）
- mac_addr=00\\:90\\:F5\\:F7\\:39\\:B0 　//网卡的mac地址（初次运行自动获取），若修改此项，注意"\\"转义
- password=8888 　　　　　　　//用户密码
- is_change=false　　//用于检测配置文件是否发生改动，如果手动修改了配置文件，请将此项置为true
<br><br>
成功运行一次后，配置文件默认不会发生改动，下次运行自动读取配置文件信息进行拨号认证，不会再重新获取服务器ip地址、本地ip地址、网卡mac地址。如果配置文件信息不正确导致无法认证，直接删除配置文件，再次执行
```
java Supplicant -u 用户名 -p 密码 
```
即可自动生成配置文件。<br>
注意：自动获取本地网卡信息会读取电脑有线网卡的mac、ip，拨号认证前，请将网卡设置为自动获取（适用于dhcp自动获取）,如果校园网不支持dhcp，请自行修改网卡ip地址、网关等信息。如果电脑存在多张有线物理网卡，导致无法正确获取网卡信息，请修改配置文件的mac_addr和local_ip两项内容。<br>
