package com.ls.hybridEncryption;

import com.ls.asymmetricCrypto.ElGamal;
import com.ls.asymmetricCrypto.ElGamalCT;
import com.ls.asymmetricCrypto.ElGamalSK;

import java.math.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.io.*;

public class HybridEncryption { // hybrid encryption: El Gamal + CBC-AES

    private static final SecureRandom sc = new SecureRandom();

    public static void main(String[] args) throws IOException {
        String msg = "aaaaaaaaaaaaaaaaaaaaaaa11111111222222222222222226666666666666666666666"; //string to encrypt
        //Setup
        // Setup El Gamal - in a real implementation it is suggested to choose at least 2048 bits of security.
        // We keep a low security parameter to execute the program fastly during the test
        ElGamalSK SK = ElGamal.Setup(64);
        // Create an IV for AES in CBC mode
        byte[] ivBytes = new byte[16];
        sc.nextBytes(ivBytes);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        // Encryption
        BigInteger M; // set M to a random message in the message space of El Gamal
        M = new BigInteger(SK.PK.securityparameter, sc);
        M = M.mod(SK.PK.p);
        ElGamalCT CT = ElGamal.Encrypt(SK.PK, M); // Encrypt M with El Gamal
        try {
            // hash M to a byte array and put the result in keyBytes that will be used to generate a key for AES128
            MessageDigest h = MessageDigest.getInstance("SHA256");
            h.update(M.toByteArray());
            byte[] keyBytes = h.digest(); // keyBytes=Hash(M)
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES"); // use keyBytes to generate an AES key
            byte[] input = msg.getBytes(); // convert the msg string to a byte array that will be encrypted under CBC-AES
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");  // encrypt array input under the key derived from M at previous steps
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
            int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
            ctLength += cipher.doFinal(cipherText, ctLength);
            // cipherText encrypts the byte array input under the key derived from M
            // decryption
            M = ElGamal.Decrypt(CT, SK); // decrypt M
            h.update(M.toByteArray()); // derive the AES key from M
            keyBytes = h.digest();
            key = new SecretKeySpec(keyBytes, "AES"); // key is Hash(M)
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            // decrypt the plaintext using the AES key computed before
            byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);
            System.out.println("plain : " + new String(plainText)+ " (" + ptLength + " bytes)");
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}