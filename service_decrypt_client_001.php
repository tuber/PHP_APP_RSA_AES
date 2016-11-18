<?php
/**
 *
 * 这里是第三步，主要工作是两个：
 *  1.服务端解密客户端传过来的参数
 *  2.加密返回对应参数的数据和服务端的aeskey 密钥。
 *具体如下：
 *
 *客户端传过来他自己的aes key ，和data 数据，这两个都加密了。
 *服务端需要用自己的私钥解开客户端传过来的aes key（因为此客户端aes key
 *是用第一步骤传给客户端的服务端公钥加密的）
 *拿到解密后的aes key 串后，然后用aes key 解密data数据
 *
 */

include_once('server_rsa_crypt.php');

include_once('lib_aes.php');
//服务端私钥
  $private_key = "-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCpS7mxdU6svbDcs10qbq9f9t5D4yfqC1jLmZD3GDD4D/8TbNkf
vcYDvde6nyPRSxrnzl9YmZhJKlP2iCIwdwwmW6yulXZyvPurfN/1AJt4JYDxnN/q
u1bSG5DZMribLsR2dlfA5J0D6lQ7g40eSgp4D6UWy8ezLy6UWFQCrnUHEQIDAQAB
AoGAQCQeoKtvOWdNIPEb9T2mWFdx8oqXzsapx8nQ8K1LsFBvNe7hfHMsGLLOjzhI
G7223eiEm07mMaJF2XvOaEpSYX/qQ1LZRSdBrzCec1lcDbB95dcRg9NmgBuCpUxE
3SGYm3VB8rurfsrRUUYoIbjWz8qyuIGdMbaNkHG/CpnUYpkCQQDfWYDYtQ3DxCt+
JBoLfuCykk8+nIV12CIYb023naoR2s/aQQRk9BkGCkDrdOAgZAN3BGOHYseKAfTP
nARDzfiDAkEAwgtYfgCDTOfW5/kJK1lZO21CdCCZnePwGYmWDLPzNiJIn8k0U6Ig
9GmxG+0GKzY71XO8W3Nh18ilZbX9dYel2wJASQ+AJGNlc0pyZ7rrgiMo4YEWxwZw
adIfpRqTs6KxhVGseFqYU2W94cns3pjG0BGnSIF5BUp8t1pYeKkyg/OWfQJBAK1w
mq41IycQaoR5kfqPKDT32dgWc3gvDqKk2duM1KzkQ+meXAkM90u/VLDTURo6pYyK
oCdVoHTRQRUCcAQnNNUCQQCO/zDRaY+5ssjPqj77eJqWfAhtbSDRRw+NurmUSas1
FT1cD5nil+uT48bIRoC5nk/XWfvAvMg/Yw5bslGUNx7f
-----END RSA PRIVATE KEY-----";

//客户端第二步传过来的的参数2-2,就是客户端aes key，对称加密的key
$client_aes_key_encrypt="iZeNcM4F6dTeSUj6NqC3OX6i34vl+0K4OSX15757xq/2a2EonIGdUBNyaTMIQQYCqeMp8JA6vC5f1PceWVeA9b79valORJYmcdYRfDbp9T8Vngjvqxlw2HIKy4xU+Kx9eu2sIJk2buLYEMLTBrsGUPFBgVS4jfRKvezGM/Qp3cs=";

//客户端发过来的参数 2-1，就是data部分,一般情况为客户端传给服务端的参数
$client_to_server_data_aes_encrypt="cUirbFdz56lbFHnz1+f+wRHHGSzOq1I3xbCigMfQIJI=";

$obj=new server_rsa_crypt();

$client_aes_key_decrpyt=$obj->decrypt($client_aes_key_encrypt);//服务端用私钥解开x，拿到客户端aes的key

var_dump($client_aes_key_decrpyt);//60a1334fd8a29962d8c12d318b3175cf，成功拿到

// 服务器解开来自客户端传递的data内容，第一个参数为aes key，第二个参数为 内容
function aes_decrypt($client_aes_key_decrpyt, $data)
    {

        $iv = 'QIAMTBdCgt27fciHx6ALIB=!';//此处iv 需要和客户端加密iv 相同

        $lib_aesencrypt = new lib_aesencrypt($client_aes_key_decrpyt, base64_decode($iv), 'PKCS7', 'cbc', 'base64');
        $de_content = $lib_aesencrypt->decrypt($data);
        return $de_content;
    }


  var_dump(aes_decrypt($client_aes_key_decrpyt,$client_to_server_data_aes_encrypt));
  /**
   * 以上结果为：
   * //string(32) "60a1334fd8a29962d8c12d318b3175cf"
     string(27) "你好，服务端，NO.001"
     [Finished in 0.4s]
   *
   */
//至此，服务端完成了接收第一次客户端的请求，下面我们将针对客户端的数据做处理，进行加密并一并给客户端返回


//在第一步中，服务端已经拿到了客户端的public key，所以，这次服务端需要把自己的aes key，生成之后用客户端公钥加密，并且服务端返回给客户端的数据用服务端的aes key 加密，把两个参数一并返回客户端

//注意以下为服务端生产的内容

 function create_server_aes_key()
    {
        $size = mcrypt_get_iv_size(MCRYPT_CAST_256, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($size, MCRYPT_DEV_URANDOM);
        // $key = hash_pbkdf2('md5', 'fwkjb3ljfbizgxc93b', $iv, 8000, 0, false);
        $key = hash_pbkdf2('md5', 'iloveyourhahahha', $iv, 8000, 0, false);

        return $key;
    }

    echo "服务端的aeskey为：".$server_aes_key=create_server_aes_key();//1aaafdc6be75321e0b7108f3ba7e1e4e

    //客户端（手机）的公钥
 $client_public_key = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDI3S0tUtLCLztMG9ML2RKl2+kY
f9ijiJF+bfZFD3YzZVdTNUtmpGAbt1F0GKgKs6OMiT7KeWajHD4ub+cCYa3FChgJ
aAWEwnwtci2wiPK5IvLV3yrwrCXvYHABsjsgR2Ne3WN1KAMAjtKfJEZCwheKwcVT
GZjcg10ZG5hyiF2FxQIDAQAB
-----END PUBLIC KEY-----";

$client_public_key = openssl_pkey_get_public($client_public_key);

 if (openssl_public_encrypt($server_aes_key, $encrypted, $client_public_key)){
          //由于加密后为二进制数据，为了展示和传输，base64_en一下，解密同
          $server_aes_key_encrpyt = base64_encode($encrypted);
        }

        echo "加密后的服务端aes key为:".$server_aes_key_encrpyt;//SCtNUp2202flGq4X+Gf3WxkSAnHzfBZ8EWqR5YLGTi6SvZK2Opt+TKvZNnI9Cq+Heq22xu6jbdyS8jxkUKcHLteBwM1nHveVtVBgmz+0B8MvzR5bUq92vGRfzdn6bo1PapkZwJ41BS04g0ODuQD2HinYtPyV0qbim+kx8yNjBOA=

//我们把服务端给客户端 的返回数据用服务端的aes key 加密，并反回

$server_to_client_data="你好，客户端，我收到了你的消息'你好，服务端，NO.001',我们之间没人能看透";

$iv="QIAMTBdCgt27fciHx6ALIB=!";//这个是服务端aes加密的串自定义，但是我不知道怎么生成合适的。和解密时也要保持一致

$aes_obj=new lib_aesencrypt($server_aes_key, base64_decode($iv), 'PKCS7', 'cbc', 'base64');
$server_to_client_data_aes_encrypt = $aes_obj->encrypt($server_to_client_data);

echo "服务端给客户端端加密后消息:".$server_to_client_data_aes_encrypt;
//RbzoLTB8qukXL2Z1W4a+NajHHLFcn/bE47XL+YeMaxbE9kVGQ6mR/ij6TeL19PC8sGW9TTRvo7oWopk8qJxvsW5gFM1ft7Cb6FU/trgWqcy2+lb3XuBxU1Ie3vUY+aE0Ul5/c6n706nFQPnWQl/eKA==

echo "\n";
echo $de_content = $aes_obj->decrypt($server_to_client_data_aes_encrypt);
//最后需要把上面两个拼接，给客户端
$send_data=array(

    "a"=>$server_to_client_data_aes_encrypt,
    "b"=>$server_aes_key_encrpyt,
  );
