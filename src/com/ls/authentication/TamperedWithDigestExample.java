package com.ls.authentication;

import com.ls.utils.AESUtils;
import com.ls.utils.Utils;

import java.lang.reflect.Array;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class TamperedWithDigestExample {


    public static void main(String[] args) throws Exception {

        SecureRandom r = new SecureRandom();

        IvParameterSpec ivSpec = AESUtils.genCTRIv(r);
        Key key = AESUtils.genKey(128, r);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        String input = "Transfer 0000100";
        System.out.println("input : " + new String(input.getBytes()));

        // encryption step
        MessageDigest hash = MessageDigest.getInstance("SHA256");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hash.getDigestLength())];
        int ctLength = cipher.update(input.getBytes(), 0, input.length(), cipherText, 0);
        hash.update(input.getBytes());
        byte[] h = hash.digest();
        ctLength += cipher.doFinal(h, 0, hash.getDigestLength(), cipherText, ctLength);
        // tampering step
        System.out.println("Tampering first digit...");
        cipherText[9] ^= '0' ^ '9';
        hash = MessageDigest.getInstance("SHA256");
        hash.update("Transfer 9000100".getBytes());
        byte[] h2 = hash.digest();
        for (int i = 16; i < 16 + hash.getDigestLength(); i++)
            cipherText[i] ^= h[i - 16] ^ h2[i - 16];
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int messageLength = plainText.length - hash.getDigestLength();
        hash.update(plainText, 0, messageLength);
        byte[] messageHash = new byte[hash.getDigestLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        String plainTextString = new String(plainText).substring(0, messageLength);
        System.out.println("plain : " + plainTextString + " - verified: " + MessageDigest.isEqual(hash.digest(), messageHash));
    }
}
