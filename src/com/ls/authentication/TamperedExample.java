package com.ls.authentication;

import com.ls.utils.AESUtils;
import com.ls.utils.Utils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * Tampered message, plain encryption, AES in CTR mode
 */
public class TamperedExample {

    public static void main(String[] args) throws Exception {

        SecureRandom r = new SecureRandom();

        IvParameterSpec ivSpec = AESUtils.genCTRIv(r);
        Key key = AESUtils.genKey(128, r);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        String input = "Transfer 0000100";
        System.out.println("input : " + new String(input.getBytes()));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        // tampering step
        System.out.println("Tampering first digit...");
        cipherText[9] ^= '0' ^ '9';
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + new String(plainText));

    }
}
