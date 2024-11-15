---
title: 应急响应靶场训练WP
---

*作者：Narcher*	*时间：2024/5/28*	*分类：writeup*

<!--more-->

## 前言

自己这一块一直是个缺口，虽说靶场针对的事件不是很全，但也算能查漏补缺一部分了



## 正文

### 应急响应靶机--Linux(1)

#### 挑战内容

前景需要：小王急匆匆地找到小张，小王说“李哥，我dev服务器被黑了”，快救救我！！

挑战内容：

黑客的IP地址

遗留下的三个flag

凭据：root/defend	defend/defend

#### 解题

1.查看当前主机最近的用户登录情况：

```shell
sudo grep "Accepted" /var/log/secure* | awk '{print $1,$2,$3,$9,$11}'
```

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716878552002.png" alt="1716878552002" style="zoom:67%;" />

可见之前有一个以root身份登录的ip，此为黑客的ip地址

2.进入root权限，`sudo -s`

查看历史命令history，发现第一个flag：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716878873693.png" alt="1716878873693" style="zoom: 80%;" />

从黑客执行的历史命令中我们可以看出黑客更改了rc.local文件，我们直接cat查看具体内容：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716879142653.png" alt="1716879142653" style="zoom:67%;" />

获取到第二个flag

3.此时，黑客以及完成了root权限的获取以及权限维持的操作，基本上就结束了，我们去看看黑客是怎么打进来的

在`cat /etc/passwd`的时候发现存在redis服务，猜测存在redis未授权漏洞，我们来测试一下：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716880054098.png" alt="1716880054098" style="zoom: 67%;" />

可见开启服务后直接登录成功，我们去查看redis配置文件，`cat /etc/redis.conf`：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716880199264.png" alt="1716880199264" style="zoom: 50%;" />

获取到第三个flag

或者我们还能去查看一下历史修改的文件，`rpm -Vf /usr/bin/*`（感觉这个命令很有用）：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716880998862.png" alt="1716880998862" style="zoom:50%;" />

从上边也能看到黑客曾经修改过的文件

到了这步并未结束，我们还可以通过redis的连接日志去反推黑客的ip地址，先查看一下redis日志文件等级：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716880579914.png" alt="1716880579914" style="zoom:67%;" />

发现为verbose，那么就会包含着请求和响应的内容，黑客从这里打进来就必然会有记录

我们去查看redis的日志文件

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716880821941.png" alt="1716880821941" style="zoom:67%;" />

发现黑客ip为192.168.75.129

到了这一步，这个靶机就基本上结束了



### 应急响应靶机--Linux(2)

#### 挑战内容

前景需要：看监控的时候发现webshell告警，领导让你上机检查你可以救救安服仔吗！！

挑战内容：

1,提交攻击者IP

2,提交攻击者修改的管理员密码(明文)

3,提交第一次Webshell的连接URL(http://xxx.xxx.xxx.xx/abcdefg?abcdefg只需要提交abcdefg?abcdefg)

3,提交Webshell连接密码

4,提交数据包的flag1

5,提交攻击者使用的后续上传的木马文件名称

6,提交攻击者隐藏的flag2

7,提交攻击者隐藏的flag3

凭据：root/Inch@957821.

（注意密码第一个字符为大写的i）

#### 解题

因为涉及宝塔的编码问题，而靶机正好开放了22端口，我就直接用ssh连接了

1.首先去查看当前主机的用户登录情况：

```shell
sudo grep "Accepted" /var/log/secure* | awk '{print $1,$2,$3,$9,$11}'
```

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716884670505.png" alt="1716884670505" style="zoom:67%;" />

192.168.58.1是我本机ip，那么192.168.20.1就是黑客的ip了

或者直接登录宝塔，查看日志：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716885097311.png" alt="1716885097311" style="zoom:50%;" />

2.至于攻击者修改的管理员密码(明文)，我们去查看一下/etc/passwd：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716885502864.png" alt="1716885502864" style="zoom:67%;" />

可见存在mysql服务，再去看看系统中所有TCP和UDP协议的监听端口以及这些端口上活动的连接和相关程序的信息：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716885808028.png" alt="1716885808028" style="zoom:67%;" />

那么管理员的密码（明文）差不多就是mysql数据库里的密码，并且需要md5解密

从宝塔数据库界面获取到数据库用户名和密码：kaoshi/5Sx8mK5ieyLPb84m

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716886090087.png" alt="1716886090087" style="zoom:67%;" />

登录成功

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716886147059.png" alt="1716886147059" style="zoom:67%;" />

之后依次输入以下命令，`show databases;`，`use kaoshi;`，`show tables;`，`select * from x2_user;`，即可获取到管理员密码的密文：`f6f6eb5ace977d7e114377cc7098b7e3`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716886484503.png" alt="1716886484503" style="zoom:67%;" />

之后md5解密即可获取到明文：`Network@2020`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716886616362.png" alt="1716886616362" style="zoom: 50%;" />

3.之后是去查找第一次Webshell的连接URL，我们把靶机中的流量文件拿出来用wireshark分析一下：

（很奇怪，我Xftp传输失败了，于是我直接从宝塔界面里下载的）

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716887701736.png" alt="1716887701736" style="zoom:50%;" />

可看出是index.php?user-app-register

3.从上图可看出，Webshell连接密码：Network2020

或者从宝塔中添加一个域名进行php网站的访问，从后台可看到：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716888142015.png" alt="1716888142015" style="zoom:50%;" />

4.查找提交数据包的flag1，直接从wirshark里看数据包1：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716888338341.png" alt="1716888338341" style="zoom:50%;" />

得到flag1：`flag1{Network@_2020_Hack}`

5.至于攻击者使用的后续上传的木马文件名称，攻击者既然上传了该木马文件，那就八成会访问，我们继续去看看流量包里的http流，发现除了index.php?user-app-register之外，还有version2.php，我们去查看一下index.php?user-app-register中POST的具体内容：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716889428679.png" alt="1716889428679" style="zoom:67%;" />

发现是冰蝎的马，之后在version2.php中http传输的都是加密过的数据了

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716889633638.png" alt="1716889633638" style="zoom:67%;" />

故攻击者使用的后续上传的木马文件为version2.php

6.要看隐藏的flag2，直接去宝塔上看文件的修改日期：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716892864281.png" alt="1716892864281" style="zoom: 50%;" />

发现多了一个奇奇怪怪的.api文件夹，且其修改时间正好和我们做第一问的时候黑客的登录时间相仿，故猜测flag2在其中

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716892944562.png" alt="1716892944562" style="zoom: 50%;" />

如上时间中，alinotify.php的修改时间最为特别，猜测是黑客将api文件夹复制过来后又单独对该文件进行了更改，因此查看该文件获取flag2：`flag{bL5Frin6JVwVw7tJBdqXlHCMVpAenXI9In9}`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716893046307.png" alt="1716893046307" style="zoom:67%;" />

7.至于隐藏的flag3，位于history中：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716893138529.png" alt="1716893138529" style="zoom:67%;" />

或者直接env查看环境变量：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716893189007.png" alt="1716893189007" style="zoom:50%;" />



### 应急响应靶机--Web1

#### 挑战内容

前景需要：

小李在值守的过程中，发现有CPU占用飙升，出于胆子小，就立刻将服务器关机，并找来正在吃苕皮的hxd帮他分析，这是他的服务器系统，请你找出以下内容，并作为通关条件：

1.攻击者的shell密码

2.攻击者的IP地址

3.攻击者的隐藏账户名称

4.攻击者挖矿程序的矿池域名(仅域名)

5.有实力的可以尝试着修复漏洞

凭据：administrator/Zgsf@admin\.com

#### 解题

1.打开虚拟机看到phpstudy，我们直奔其网站根目录，用火绒查杀去扫：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716899848026.png" alt="1716899848026" style="zoom:50%;" />

发现shell，我们去查看（有点尴尬，我刚扫完，系统自动给我把🐎删了，没快照，只能重新开一次了）

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716901048077.png" alt="1716901048077" style="zoom:50%;" />

典型冰蝎马，shell密码为rebeyong

2.要获取攻击者IP，直接去看日志就好了，去网站根目录搜log，发现C:\phpstudy_pro\Extensions\Apache2.4.39\logs\access.log有东西：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716901355040.png" alt="1716901355040" style="zoom:50%;" />

对着登录页面使劲请求，盲猜爆破账号密码，故192.168.126.1即为攻击者IP

3.要找攻击者隐藏账户名称，直接去控制面板看就好了：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716901479459.png" alt="1716901479459" style="zoom:50%;" />

也可以直接去看注册表或者事件管理器，甚至直接去看文件夹里的用户：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716902178747.png" alt="1716902178747" style="zoom:50%;" />

4.要看攻击者矿池程序的矿池域名，我们得去恶意用户的文件夹下找到矿池程序：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716902271214.png" alt="1716902271214" style="zoom:50%;" />

该图标为pyinstaller打包，使用pyinstxtractor进行反编译(https://github.com/extremecoders-re/pyinstxtractor)

再使用在线pyc反编译[python反编译 - 在线工具 (tool.lu)](https://tool.lu/pyc/)

即可获取源码进而得到矿池域名：`wakuang.zhigongshanfang.top`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716902793063.png" alt="1716902793063" style="zoom:50%;" />



### 应急响应靶机--Web2

#### 挑战内容

前景需要：小李在某单位驻场值守，深夜12点，甲方已经回家了，小李刚偷偷摸鱼后，发现安全设备有告警，于是立刻停掉了机器开始排查。

这是他的服务器系统，请你找出以下内容，并作为通关条件：

1.攻击者的IP地址（两个）？

2.攻击者的webshell文件名？

3.攻击者的webshell密码？

4.攻击者的伪QQ号？

5.攻击者的伪服务器IP地址？

6.攻击者的服务器端口？

7.攻击者是如何入侵的（选择题）？

8.攻击者的隐藏用户名？

凭据：administrator/Zgsf@qq\.com

#### 解题

1.要看攻击者的IP地址，还是去看日志：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716904307740.png" alt="1716904307740" style="zoom:50%;" />

其中一个IP是192.168.126.135，这个是传🐎连🐎的IP，还有一个，猜测是远程登录的IP，等下边再说

2.攻击者的webshell文件名，很简单，直接把根目录放火绒里扫就行了：`system.php`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716903972903.png" alt="1716903972903" style="zoom:50%;" />

3.攻击者webshell密码直接去看木马文件即可：`hack6618`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716904100802.png" alt="1716904100802" style="zoom:50%;" />

4.提到QQ号，这就不得不去看Tencent Files了，也算是QQ的一个特性吧，会在该文件下以QQ号为名创建一个文件夹：`777888999321`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716904639728.png" alt="1716904639728" style="zoom:50%;" />

5.攻击者的伪服务器IP，这个是在QQ接收的文件中找到的：`255.256.66.88`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716904850330.png" alt="1716904850330" style="zoom:50%;" />

6.端口也出来了：`65536`（当然都是伪的）

7.至于攻击者是怎么打进来的，这个去翻翻日志就知道了：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716905141172.png" alt="1716905141172" style="zoom:50%;" />

在图中文件里，攻击者IP反复请求FTP进行登录爆破，最终成功以admin身份登录

8.至于隐藏用户名，我们去注册表查看即可，Win+R输入regedit：hack887（后边的$为隐藏的意思）

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716905240749.png" alt="1716905240749" style="zoom:50%;" />

现在，我们还差第一问的另一个IP地址，这个我们之前就猜测是远程登录用的IP，现在我们得知了攻击者的隐藏用户，接下来去事件查看器即可查看其另一个IP：192.168.126.129

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716905697895.png" alt="1716905697895" style="zoom:50%;" />

至此，本靶机结束



### 应急响应靶机--Web3

#### 挑战内容

前景需要：小苕在省护值守中，在灵机一动情况下把设备停掉了，甲方问：为什么要停设备？小苕说：我第六感告诉我，这机器可能被黑了。

这是他的服务器，请你找出以下内容作为通关条件：

1. 攻击者的两个IP地址
2. 隐藏用户名称
3. 黑客遗留下的flag【3个】

本虚拟机的考点不在隐藏用户以及ip地址，仔细找找把。

凭据：administrator/xj@123456

#### 解题

环境没起出来，直接看官方题解了：

https://mp.weixin.qq.com/mp/wappoc_appmsgcaptcha?poc_token=HLwhV2aj1vpy_D8q_3g_qGiJjIPIyisfz6bgKTEs&target_url=https%3A%2F%2Fmp.weixin.qq.com%2Fs%2FYvCL27cfX5pfD0LiVt4EeA

下面写一下看完后的总结：

1.攻击者IP地址直接去日志文件看

2.隐藏用户可以去控制面板，也可去注册表等查看

3.任务计划程序里可能会看到可疑任务，进而查看可疑任务的具体内容会有收获

4.Web应用中可能存在明显的漏洞导致已经被黑客入侵，例如本题中的Z-blog



### 应急响应靶机--近源渗透OS-1

#### 挑战内容

前景需要：小王从某安全大厂被优化掉后，来到了某私立小学当起了计算机老师。某一天上课的时候，发现鼠标在自己动弹，又发现除了某台电脑，其他电脑连不上网络。感觉肯定有学生捣乱，于是开启了应急。

1.攻击者的外网IP地址

2.攻击者的内网跳板IP地址

3.攻击者使用的限速软件的md5大写

4.攻击者的后门md5大写

5.攻击者留下的flag

凭据：Administrator/zgsf@2024

#### 解题

直接CMD mstsc远程桌面连接了

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716984318342.png" alt="1716984318342" style="zoom:50%;" />

1.把桌面文件放到奇安信威胁情报中心里进行分析，发现如下文件存在恶意宏，且存在攻击者的外网IP：8.219.200.130

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716985176939.png" alt="1716985176939" style="zoom:50%;" />

2.至于其内网IP，没啥思路，去看看有无隐藏文件什么的，把文件夹中改成显示隐藏文件：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716985281344.png" alt="1716985281344" style="zoom:50%;" />

发现隐藏文件：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716985327067.png" alt="1716985327067" style="zoom:50%;" />

攻击者内网IP：192.168.20.129

3.至于限速软件，我们只能去翻C盘文件发现可疑文件：C:\PerfLogs\666\666\777\666\666\666\666\666\666\666\666\666\666\666\p2pover4.34.exe、

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716985529197.png" alt="1716985529197" style="zoom:50%;" />

然后去搜索引擎搜一下：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716985697081.png" alt="1716985697081" style="zoom:50%;" />

限速文件就是它了，至于MD5，丢奇安信威胁情报中心就出来了

4.后门在5次shift键里，而其后门文件自然就是攻击者替换了C:\Windows\System32\sethc.exe文件：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1716986058819.png" alt="1716986058819" style="zoom:50%;" />

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/image-20240529203117363.png" alt="image-20240529203117363" style="zoom:50%;" />

5.flag如上如所示，按5次shift键就出来了



### 应急响应靶机--挖矿

#### 挑战内容

前景需要：机房运维小陈，下班后发现还有工作没完成，然后上机器越用越卡，请你帮他看看原因。

挑战内容：

攻击者的IP地址

攻击者开始攻击的时间

攻击者攻击的端口

挖矿程序的md5

后门脚本的md5

矿池地址

钱包地址

攻击者是如何攻击进入的

凭据：Administrator/zgsf@123

#### 解题

没有安装vmware Tools，直接mstsc连接即可，最近新安了蓝队应急响应工具箱，正好试一试

1.可见登录失败的日志中IP：192.168.115.131反复出现，故可猜测该IP为攻击者IP

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1717037516452.png" alt="1717037516452" style="zoom:50%;" />

2.至于开始攻击的时间，直接去看上图的Date：`2024-05-21 20:25:22`

3.至于攻击者攻击的端口，还是看上边那个图，Workstation显示NtLmSap，经搜索得知是攻击者爆破3389端口

4.至于挖矿程序md5，去任务管理器里找：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1717038436568.png" alt="1717038436568" style="zoom:50%;" />

就这个资源占用最多，直接计算hash

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1717038731846.png" alt="1717038731846" style="zoom:50%;" />

5.至于后门脚本，用火绒剑扫：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1717039161561.png" alt="1717039161561" style="zoom:50%;" />

发现可疑文件，打开看看：

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/1717039305310.png" alt="1717039305310" style="zoom:50%;" />

一眼与C3Pool挖矿有关，故此为挖矿脚本，计算其hash即可

5.矿池地址如上图所示：`c3pool.org`

6.钱包地址也如上图所示：`4APXVhukGNiR5kqqVC7jwiVaa5jDxUgPohEtAyuRS1uyeL6K1LkkBy9SKx5W1M7gYyNneusud6A8hKjJCtVbeoFARuQTu4Y`

<img src="%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94%E9%9D%B6%E5%9C%BA%E8%AE%AD%E7%BB%83WP/image-20240530112944579.png" alt="image-20240530112944579" style="zoom:50%;" />

7.攻击者如何进入的，这个其实前边已经提到了：暴力破解3389远程登录密码，填`暴力破解`即可
