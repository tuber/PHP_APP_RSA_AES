<?php


/**
 * 这里假定为 客户端（App）公钥和私钥。私钥跑一遍Android程序就能拿到。
 * 注意：
 * 1.每行必须64个字符
 *   可用以下方式做特殊处理。
 *    $client_public_key = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($client_public_key, 64,
 *     "\n", true) . "\n-----END
 *    PUBLIC KEY-----";来处理
 * 2.crypt的意思是 地窖，一般指的教堂地下室^_^
 * 3.encrypt 每次加密的结果不同，估计是加了干扰字符
 * 4.可用下面的single eg 来验证此RSA的正确性。
 */
class client_rsa_crypt {

//APP端的公钥
private $public_key = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDI3S0tUtLCLztMG9ML2RKl2+kY
f9ijiJF+bfZFD3YzZVdTNUtmpGAbt1F0GKgKs6OMiT7KeWajHD4ub+cCYa3FChgJ
aAWEwnwtci2wiPK5IvLV3yrwrCXvYHABsjsgR2Ne3WN1KAMAjtKfJEZCwheKwcVT
GZjcg10ZG5hyiF2FxQIDAQAB
-----END PUBLIC KEY-----";

//APP端的私钥

private $private_key = "-----BEGIN PRIVATE KEY-----
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

            throw new Exception('encrypt wrong');
        }

        return $data;
    }

    public function decrypt($data) {
        if (openssl_private_decrypt(base64_decode($data), $decrypted, $this->privkey))
            $data = $decrypted;
        else
            $data = '';

        return $data;
    }

}

// single eg:目的是保证此ras对是可用的

// $c =new client_rsa_crypt();

// $a=$c->encrypt('hello');

// $b=$c->decrypt($a);

// var_dump($a);

// var_dump($b);
