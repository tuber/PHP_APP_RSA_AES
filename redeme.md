共有七个文件
其中包括三个类文件
1. `lib_aes.php` aes对称加密解密类
2. `server_rsa_crypt.php` 服务端RSA公钥私钥非对称加密解密类
3. `client_rsa_crypt.php` 客户端RSA公钥私钥非对称加密解密类

四个过程文件,其中文件中有注释和exapmle数据

- 第一步：客户端和服务端交换密钥（明文）-`service_client_exchange.php`
- 第二步:客户端发起带参数请求（加密后）- `client_generate_aeskey.php`

- 第三步：服务端解密客户端请求
   并加密服务端数据（先解密，后加密）-`service_decrypt_client_001.php`

- 第四步：客户端解密服务端数据（先解密，..加密）-`client_decrypt_server.php`

And So on...

