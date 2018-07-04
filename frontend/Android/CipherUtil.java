package com.cryptographysolution.encrypt;

import android.util.Base64;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.spongycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.ECDH;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class CipherUtil {
    private static final String TRANSFORMATION = "ECDH";

    public CipherUtil() {
    }

    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator instance = ECDH.getInstance("ECDH", "SC");
        ECGenParameterSpec secp256k1 = new ECGenParameterSpec("secp384r1");
        instance.initialize(secp256k1);
        KeyPair keyPair = instance.generateKeyPair();
        return keyPair;
    }

    public static String getPrivateKey(KeyPair pair) {
        ECPrivateKey privateKey = (ECPrivateKey)pair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        String privateKeyAsPEMKey = getPrivateKeyAsPEM(byte2Base64(bytes));
        return privateKeyAsPEMKey.trim();
    }

    public static String getPublicKey(KeyPair pair) {
        ECPublicKey publicKey = (ECPublicKey)pair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        String publicKeyAsPEM = getPublicKeyAsPEM(byte2Base64(bytes));
        return publicKeyAsPEM.trim();
    }

    public static String getShareKey(String privateKeyStr, String publicKeyStr) throws Exception {
        ECPrivateKey privateKey = string2PrivateKey(privateKeyStr);
        ECPublicKey ecPublicKey = string2PublicKey(publicKeyStr);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "SC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(ecPublicKey, true);
        byte[] bytes = keyAgreement.generateSecret();
        return byte2Base64(bytes).trim();
    }

    public static String keyEncrypt(String content, String shareKey, String nonce) {
        SecretKey secretKey = new SecretKeySpec(hex2Bytes(encrypt(shareKey, "SHA-256")), "AES");
        byte[] bytes = content.getBytes();

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SC");
            cipher.init(1, secretKey, new IvParameterSpec(hex2Bytes(nonce)));
            bytes = cipher.doFinal(bytes);
        } catch (Exception var6) {
            var6.printStackTrace();
        }

        return bytes2Hex(bytes).trim();
    }

    public static String keyDecrypt(String content, String shareKey, String nonce) {
        SecretKey secretKey = new SecretKeySpec(hex2Bytes(encrypt(shareKey, "SHA-256")), "AES");
        byte[] bytes = new byte[0];

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SC");
            cipher.init(2, secretKey, new IvParameterSpec(hex2Bytes(nonce)));
            bytes = cipher.doFinal(hex2Bytes(content));
        } catch (Exception var6) {
            var6.printStackTrace();
        }

        return (new String(bytes)).trim();
    }

    private static String getPrivateKeyAsPEM(String s) {
        StringBuilder sb = new StringBuilder(s);
        sb.insert(0, "-----BEGIN PRIVATE KEY-----\n");
        sb.append("-----END PRIVATE KEY-----");
        return sb.toString();
    }

    private static String getPublicKeyAsPEM(String s) {
        StringBuilder sb = new StringBuilder(s);
        sb.insert(0, "-----BEGIN PUBLIC KEY-----\n");
        sb.append("-----END PUBLIC KEY-----");
        return sb.toString();
    }

    private static ECPrivateKey string2PrivateKey(String priStr) throws Exception {
        priStr = priStr.replace("-----BEGIN PRIVATE KEY-----", "");
        priStr = priStr.replace("-----END PRIVATE KEY-----", "");
        priStr = priStr.replace(" ", "");
        byte[] keyBytes = base642Byte(priStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "SC");
        ECPrivateKey privateKey = (ECPrivateKey)keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    private static ECPublicKey string2PublicKey(String pubStr) throws Exception {
        pubStr = pubStr.replace("-----BEGIN PUBLIC KEY-----", "");
        pubStr = pubStr.replace("-----END PUBLIC KEY-----", "");
        pubStr = pubStr.replace(" ", "");
        byte[] keyBytes = base642Byte(pubStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "SC");
        ECPublicKey publicKey = (ECPublicKey)keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    private static String bytes2Hex(byte[] bts) {
        String des = "";
        String tmp = null;

        for(int i = 0; i < bts.length; ++i) {
            tmp = Integer.toHexString(bts[i] & 255);
            if (tmp.length() == 1) {
                des = des + "0";
            }

            des = des + tmp;
        }

        return des;
    }

    private static byte[] hex2Bytes(String str) {
        if (str != null && !str.trim().equals("")) {
            byte[] bytes = new byte[str.length() / 2];

            for(int i = 0; i < str.length() / 2; ++i) {
                String subStr = str.substring(i * 2, i * 2 + 2);
                bytes[i] = (byte)Integer.parseInt(subStr, 16);
            }

            return bytes;
        } else {
            return new byte[0];
        }
    }

    private static String encrypt(String string, String type) {
        if (string != null && string.length() != 0) {
            MessageDigest md5 = null;

            try {
                md5 = MessageDigest.getInstance(type);
                byte[] bytes = md5.digest(string.getBytes());
                String result = "";
                byte[] var5 = bytes;
                int var6 = bytes.length;

                for(int var7 = 0; var7 < var6; ++var7) {
                    byte b = var5[var7];
                    String temp = Integer.toHexString(b & 255);
                    if (temp.length() == 1) {
                        temp = "0" + temp;
                    }

                    result = result + temp;
                }

                return result;
            } catch (NoSuchAlgorithmException var10) {
                var10.printStackTrace();
                return "";
            }
        } else {
            return "";
        }
    }

    private static byte[] base642Byte(String base64Str) {
        return Base64.decode(base64Str, 0);
    }

    private static String byte2Base64(byte[] b) {
        return Base64.encodeToString(b, 0);
    }

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
}
