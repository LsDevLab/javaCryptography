package com.ls.authentication;

import com.ls.utils.AESUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Encrypt Then MAC (HMAC)  example - encryption AES in CTR mode
 */
public class EncThenHMACExample {

    public static void main(String[] args) throws Exception {

        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = AESUtils.genCTRIv(random);
        Key key = AESUtils.genKey(256, random);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        String input = "Transfer 0000100";
        System.out.println("input : " + new String(input.getBytes()));

        Mac mac = Mac.getInstance("HMacSHA256");
        KeyGenerator generator = KeyGenerator.getInstance("HMacSHA256");
        generator.init(128);
        Key macKey = generator.generateKey();

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + mac.getMacLength())];
        int ctLength = cipher.update(input.getBytes(), 0, input.length(), cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        mac.init(macKey);
        mac.update(cipherText);
        byte[] t = mac.doFinal();
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        mac.init(macKey);
        mac.update(cipherText, 0, cipherText.length);
        System.out.println("plain : " + new String(plainText) + " - verified: " + MessageDigest.isEqual(mac.doFinal(), t));

    }
}
