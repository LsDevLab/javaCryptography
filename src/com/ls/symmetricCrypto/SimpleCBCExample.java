package com.ls.symmetricCrypto;

import com.ls.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class SimpleCBCExample
{
    public static void main(String[] args) throws Exception
    {
        byte[] input = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        System.out.println("Input: " + Utils.bytesToHexString(input) + " bytes: " + input.length);

        byte[] keyBytes = new byte[] {
                0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
        System.out.println("Key bytes: " + keyBytes.length);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding");

        byte[] ivBytes = new byte[cipher.getBlockSize()];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(ivBytes);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        System.out.println("IV bytes: " + ivBytes.length);

        // Alternatively, you can let the Cipher object generate an IV for you:
        // cipher.init(Cipher.ENCRYPT_MODE, key);
        // IvParameterSpec ivSpec = new IvParameterSpec(cipher.getIV());

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        // encryption
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("Cipher: " + Utils.bytesToHexString(cipherText) + " bytes: " + cipherText.length);
        // decryption
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("Plain : " + Utils.bytesToHexString(plainText) + " bytes: " + ptLength);
        // Notice that this time every block of the encrypted output is different,
        // even though you can see that the first and third blocks of the input data are the same.
    }
}