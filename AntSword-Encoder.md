```javascript
/**
 * php::RSA编码器
 * Create at: 2021/03/06 10:32:47
 */

'use strict';

/*
 * @param  {String} pwd   连接密码
 * @param  {Array}  data  编码器处理前的 payload 数组
 * @return {Array}  data  编码器处理后的 payload 数组
 */
module.exports = (pwd, data, ext={}) => {
    let n = Math.ceil(data['_'].length / 80);
    let l = Math.ceil(data['_'].length / n);
    let r = [];
    for (var i = 0; n > i; i++) {
        r.push(ext['rsa'].encryptPrivate(data['_'].substr(i * l, l), 'base64'));
    }
    let tmp1 = r.join("$");
    let tmp2 = tmp1.replace(/=/g,"#").replace(/\//g,"-");
    data[pwd] = tmp2;
    delete data['_'];
    return data;

}
```
