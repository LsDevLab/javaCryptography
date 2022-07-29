package com.ls.symmetricCrypto;

import com.ls.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SimpleCTRExample {

    public static void main(String[] args) throws Exception {

        byte[] input = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,0x07
        };
        System.out.println("Input: " + Utils.bytesToHexString(input) + " bytes: " + input.length);

        byte[]	keyBytes = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        System.out.println("Key bytes: " + keyBytes.length);

        byte[]  ivBytes = new byte[] {
                (byte) 0x23,(byte) 0x78, (byte) 0x15, (byte) 0xbf,
                (byte) 0x00,(byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        System.out.println("IV: " + Utils.bytesToHexString(ivBytes) + " bytes: " + ivBytes.length);

        Cipher cipher = Cipher.getInstance("DES/CTR/NoPadding");

        // encryption
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("Cipher: " + Utils.bytesToHexString(cipherText) + " bytes: " + ctLength);
        // decryption
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("Plain : " + Utils.bytesToHexString(plainText) + " bytes: " + ptLength);

    }

}
