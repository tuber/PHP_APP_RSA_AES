<?php

/**
 *  服务端 公钥和私钥 初始化，以及加密解密流程
 * 注意：
 * 1.每行必须64个字符
 *   可用以下方式做特殊处理。
 *    $client_public_key = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($client_public_key, 64,
 *     "\n", true) . "\n-----END
 *    PUBLIC KEY-----";来处理
 * 2.crypt的意思是 地窖，一般指的教堂地下室^_^
 * 3.encrypt 每次加密的结果不同，估计是加了干扰字符
 * 4.此rsa对 生成方法 https://segmentfault.com/a/1190000005935157
 * 5.可用下面的single eg 来验证此RSA的正确性。
 *
 */

class server_rsa_crypt {

  private $private_key = "-----BEGIN RSA PRIVATE KEY-----
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

private $public_key = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpS7mxdU6svbDcs10qbq9f9t5D
4yfqC1jLmZD3GDD4D/8TbNkfvcYDvde6nyPRSxrnzl9YmZhJKlP2iCIwdwwmW6yu
lXZyvPurfN/1AJt4JYDxnN/qu1bSG5DZMribLsR2dlfA5J0D6lQ7g40eSgp4D6UW
y8ezLy6UWFQCrnUHEQIDAQAB
-----END PUBLIC KEY-----";

    public $pubkey;
    public $privkey;

    function __construct() {
                // 获得资源类型公钥和私钥，
                $this->privkey = openssl_pkey_get_private($this->private_key);
                $this->pubkey = openssl_pkey_get_public($this->public_key);
    }

    public function encrypt($data) {
        if (openssl_public_encrypt($data, $encrypted, $this->pubkey)){
          //由于加密后为二进制数据，为了展示和传输，base64_en一下，解密同
          $data = base64_encode($encrypted);
        }
        else{

            echo 'encrypt wrong';
        }

        return $data;
    }

    public function decrypt($data) {
        if (openssl_private_decrypt(base64_decode($data), $decrypted, $this->privkey)){
            $data = $decrypted;
        }
        else{
            echo  'wrong decrypt';
        }

        return $data;
    }

}

//single eg:
// $c =new server_rsa_crypt();

// $a=$c->encrypt('1212');

// $b=$c->decrypt($a);

// var_dump($a);

// var_dump($b);
