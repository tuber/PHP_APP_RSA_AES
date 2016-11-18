<?php

/**客户端解密服务端传来的数据

 * 这里是第四步 ，也是最后一步。
 * 之前第一步（server_client_exchange.php中）：客户端请求服务端，把客户端公钥拿到，服务端把自己的公钥给客户端
 *
 * 之前第二步（client_gengrate_aeskey.php）：客户端用服务端公钥加密自己在客户端生成的aes key，并把data 用aes key 加密，一并发给服务端。
 *
 * 之前第三步：服务端接受客户端加密的数据，用服务端私钥解开客户端的aeskey，并用此aes key（在客户端生成的）解开第二步的data数据
 *             服务端根据客户端的请求参数（就是data部分），同样在服务端本地生成aes key，并用第一步拿到的客户端的公钥加密此aes key。
 *             然后用服务端的aes key 加密服务端给客户端的个性化数据（就是根据客户端参数不同传递返回的数据不同）
 *
 * 第四步客户端需要做的
 *
 * 用客户端自己的私钥解开 服务端用客户端公钥加密的，在服务端本地生成的 aes key
 * 然后用此 aes key解密服务端给客户端的个性化数据（就是根据客户端参数不同传递返回的数据不同）
 *
 *
 * 注意：客户端和服务端之间传输加密的数据每次都会改变，但是只要双方公钥密钥不变，都可以互解。
 *       另外aes key也是每次随机生成的，所以aes加密的dada数据，aes本身加密后的串，每次都会改变。
 */


include_once('client_rsa_crypt.php');

include_once('lib_aes.php');

//服务端返回给客户端的内容2-2,加密后的data
$server_to_client_data_aes_encrypt="Xb6avmn1ht2Snl3Q5OyboLsnJOd4vabXzcOheXu37LD1oTIyFP0xuBOGIQ6eMvJJumie6Jd3G5TeugxlQJzWkMqWtyr54A7N+A0uUQHtGD+umNmRAweOyWTDVJDxJF2/4ceDyEjAKUqsrysojwH2tg==";

//服务端返回给客户端的内容2-1,加密后的aes key
$server_aes_key_encrpyt="PyEb70rI38FGpuGb0bSKJYsD1pKqTFvB1ivO6KELyMzStIkfJV1+1qqLnuoxphVpwZnfq9vcACLtaJR6PeEcjTMLDKhXPTIcejmZqMSo1U3l2xsg1TD4JuTuvTcxJ6LiQ+xX1rCRTor50SzeDl7QxjtVp1+e2d85dt3QEAhO5Ss=";


// 客户端的的私钥
 $client_private_key = "-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMjdLS1S0sIvO0wb
0wvZEqXb6Rh/2KOIkX5t9kUPdjNlV1M1S2akYBu3UXQYqAqzo4yJPsp5ZqMcPi5v
5wJhrcUKGAloBYTCfC1yLbCI8rki8tXfKvCsJe9gcAGyOyBHY17dY3UoAwCO0p8k
RkLCF4rBxVMZmNyDXRkbmHKIXYXFAgMBAAECgYAclUzOfFC9jVcU14jK0NMUgxzC
fb7oVpDNuvwmi7K4UZ2Bm73lF1MN3qJasP+ItlN5tjYXPftbDrPSi94FurytYsjb
kgdQlWutgJnOCcxncHfaXvzIWIYcDl0pFw2lKzc5ZtNGSq/KMwX5F0HzepI4W5nY
VapNccNinhewKlXWAQJBAO6wSoHDKv3zgezBIkKYJWhRoZRSxRXk9zFpXANwr6AZ
J4lzSr/VICBYmQDQajMKSPQZcaFtgRQwu37RDd/GI0ECQQDXbpk2qe5AtgwVSCOr
W7Isu15gt8wiZtWxfZOBQh3XGOYS+PlTwQo+RPy3f27qlC0qcoL/3YhzYLrm/uPq
sPWFAkAlImA1F/wUTlIkV1fRLIKFXE3bGZV39otOsKmUD3ADZGZ2R+2VMr8wyRfk
vIgJMMxwzZSUHMk8Lui8riGOcvEBAkB9twipoZhrItECSkqmYKgk+mIkxpzVJnVl
UgaV02NediUsxSWZ/nhfxhpDapXrRfTlZFWVwk0yJyxqSCvwdLuRAkBOTYh7pSm0
uoWdyXQRkSmv+HxEp3psKwIE/JmtSZfbFO4NnIptF4zXL+SM0WCoU/iVtCQWxcaf
89NCj3KhQK8B
-----END PRIVATE KEY-----";



$obj=new client_rsa_crypt();

$server_aes_key_decrpyt=$obj->decrypt($server_aes_key_encrpyt);//客户端用私钥解开的是服务端用客户端公钥加密的aes 串

echo "客户端解密后的服务端的aeskey为:".$server_aes_key_decrpyt;//8ef4f302e5bc4943c8fc5d0b6ccd6677


// 客户端解开来自服务端传递的内容，第一个参数为aes key，第二个参数为 内容
$iv="QIAMTBdCgt27fciHx6ALIB=!";
$aes_obj=new lib_aesencrypt($server_aes_key_decrpyt, base64_decode($iv), 'PKCS7', 'cbc', 'base64');

echo "\n";
$de_content = $aes_obj->decrypt($server_to_client_data_aes_encrypt);

var_dump($de_content);


