package com.nalaolla.aescryptor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class AescryptorApplication {

    private static final String CHAR_NAME = "UTF-8";
    private static final String SPEC_NAME = "AES";
    private static final String CIPHER_NAME = "AES/CBC/PKCS5Padding";
    private static final String SECURE_KEY = "35q97RxB6eGPLWBB";

    public static void main(String[] args) throws JsonProcessingException {
        SpringApplication.run(AescryptorApplication.class, args);

        String secureKey = SECURE_KEY;

        Map<String,Object> param = new HashMap<>();
        param.put("userId", "testuserId");
        param.put("nickname", "테스트사용자");
        param.put("host", "snsform.co.kr");
        param.put("serviceId", "svnId");
        param.put("timestamp", System.currentTimeMillis());

        ObjectMapper mapper = new ObjectMapper();

        String data = mapper.writeValueAsString(param);
        System.out.println("data : " + data);

        String sessionKey = AescryptorApplication.encrypt(data, secureKey);
        System.out.println("sessionKey : " + sessionKey);

        String unSessionKey = AescryptorApplication.decrypt(sessionKey, secureKey);
        System.out.println("unSessionKey : " + unSessionKey);
    }


    private static final byte[] IV = new byte[16];

    public static String encrypt(String source, String key) {
        try {
            return new String(Base64.encodeBase64(encrypt(source.getBytes(), key.getBytes())), CHAR_NAME);
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
    public static String decrypt(String source, String key) {
        try {
            return new String(decrypt(Base64.decodeBase64(source.getBytes()), key.getBytes()), CHAR_NAME);
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static byte[] encrypt(byte[] source, byte[] key) {
        AlgorithmParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec newKey = new SecretKeySpec(key, SPEC_NAME);

        try {
            Cipher cipher = null;
            cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);

            return cipher.doFinal(source);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
    private static byte[] decrypt(byte[] source, byte[] key) {
        AlgorithmParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec newKey = new SecretKeySpec(key, SPEC_NAME);

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
            return cipher.doFinal(source);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }


}
