package com.licaifan.rubikcube;

import android.util.Log;

import com.cryptographysolution.encrypt.BCrypt;
import com.cryptographysolution.encrypt.CipherUtil;

import java.security.KeyPair;


public class Demo {

    public static void test() {
        try {
            KeyPair keyPair = CipherUtil.getKeyPair();
            String privateKey = CipherUtil.getPrivateKey(keyPair);
            String publicKey = CipherUtil.getPublicKey(keyPair);

            String shareKey = CipherUtil.getShareKey(privateKey, publicKey);

            String data = "1234567890";
            String s = CipherUtil.keyEncrypt(data, shareKey, "540929e21c04a3a4bef16fe3");
            String s1 = CipherUtil.keyDecrypt(s, shareKey, "540929e21c04a3a4bef16fe3");
            if (data.equals(s1)) {
                Log.d("TAG", "success");
            } else {
                Log.d("TAG", "failed");
            }
            String password = "123456";
            String hashpw = BCrypt.hashpw(password, "$2a$12$qOLGsPgVlOcQZD0Rr1XD.O");
           
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
