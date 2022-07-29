package com.ls.authentication;

import com.ls.utils.AESUtils;

import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;

/**
 * MAC (HMAC) then Encrypt example - encryption AES in CTR mode
 */
public class HMACThenEncExample {

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
        mac.init(macKey);
        mac.update(input.getBytes());
        ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, ctLength);
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int messageLength = plainText.length - mac.getMacLength();
        mac.init(macKey);
        mac.update(plainText, 0, messageLength);
        byte[] messageHash = new byte[mac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        String plainTextString = new String(plainText).substring(0, messageLength);
        System.out.println("plain : " + plainTextString + " - verified: " + MessageDigest.isEqual(mac.doFinal(), messageHash));

    }
}
