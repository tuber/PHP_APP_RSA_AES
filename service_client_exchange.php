<?php

/**
 * 这里是第一步，伪代码，伪代码，伪代码 ，可根据自身框架和业务逻辑完成
 * 主要作用:
 * 1.用于接收客户端公钥
 * 2.生成服务端的Aes KEY
 * 3.保存
 *   客户端的deviceid
 *   客户端的公钥，服务端的公钥和私钥
 *   服务端自己的Aes KEY
 *  4.最后把自己服务端公钥返回给客户端
 */

function server_client_exchange(){
        $device = lib_context::post('device_uuid', lib_context::T_STRING);
        $client_public_key = lib_context::post('c_p_k', lib_context::T_STRING);
        $client_public_key = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($client_public_key, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
        $module_crypt = new module_crypt();
        $aes_key = $module_crypt->create_server_aes_key();
        $private_key = $this->get_private_key();
        $public_key = $this->get_public_key();
        $module_crypt->add_crypt_keys_to_db($device, $private_key, $public_key, $client_public_key, $aes_key);
        $data = array('s_p_k'=>$public_key);
        $this->api_succ_nocrypt($data);
}
