<?php

include_once('client_rsa_crypt.php');

include_once('lib_aes.php');
/**
 * 通过第一步，客户端已经拿到了服务端的公钥。
 *
 * 这里是第二步，客户端生成自己的aes key,
 *
 * 现在通过服务端公钥把客户端自动随机生成的aes KEY 用服务端的RSA公钥加密,定义变量为$client_aes_key
 * 然后把客户端传送给服务端的数据用客户端自己的aes key 加密，定义为变量$client_to_server_data
 */


  function create_client_aes_key()
    {
        $size = mcrypt_get_iv_size(MCRYPT_CAST_256, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($size, MCRYPT_DEV_URANDOM);
        return hash_pbkdf2('md5', 'fwkjb3ljfbizgxc93b', $iv, 8000, 0, false);
       
    }

    create_client_aes_key();//60a1334fd8a29962d8c12d318b3175cf


// 第一步已经拿到了服务端的公钥
    $server_public_key = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpS7mxdU6svbDcs10qbq9f9t5D
4yfqC1jLmZD3GDD4D/8TbNkfvcYDvde6nyPRSxrnzl9YmZhJKlP2iCIwdwwmW6yu
lXZyvPurfN/1AJt4JYDxnN/qu1bSG5DZMribLsR2dlfA5J0D6lQ7g40eSgp4D6UW
y8ezLy6UWFQCrnUHEQIDAQAB
-----END PUBLIC KEY-----";
//用服务端公钥将客户端aes key 加密 60a1334fd8a29962d8c12d318b3175cf


 $client_aes_key="60a1334fd8a29962d8c12d318b3175cf";

 $server_public_key= openssl_pkey_get_public($server_public_key);

if (openssl_public_encrypt($client_aes_key, $encrypted, $server_public_key)){
          //由于加密后为二进制数据，为了展示和传输，base64_en一下，解密同
          $client_aes_key_encrypt = base64_encode($encrypted);
        }
        else{

            echo 'encrypt wrong';
        }

 echo "客户端给服务端加密后aes key:".$client_aes_key_encrypt;//加密后的，每次都不同
/**
 * iZeNcM4F6dTeSUj6NqC3OX6i34vl+0K4OSX15757xq/2a2EonIGdUBNyaTMIQQYCqeMp8JA6vC5f1PceWVeA9b79valORJYmcdYRfDbp9T8Vngjvqxlw2HIKy4xU+Kx9eu2sIJk2buLYEMLTBrsGUPFBgVS4jfRKvezGM/Qp3cs=
 */

//下面用客户端自己生成的 aes key 把要传输的数据加密下

$client_to_server_data="你好，服务端，NO.001";

$iv="QIAMTBdCgt27fciHx6ALIB=!";//这个串自定义，但是我不知道怎么生成合适的。和解密时也要保持一致

$aes_obj=new lib_aesencrypt($client_aes_key, base64_decode($iv), 'PKCS7', 'cbc', 'base64');

echo "客户端给服务端加密后消息:".$client_to_server_data_aes_encrypt = $aes_obj->encrypt($client_to_server_data);
//cUirbFdz56lbFHnz1+f+wRHHGSzOq1I3xbCigMfQIJI=

//最后需要把上面两个拼接，给客户端
$send_data=array(

    "a"=>$client_to_server_data_aes_encrypt,
    "b"=>$client_aes_key_encrypt,
  );




