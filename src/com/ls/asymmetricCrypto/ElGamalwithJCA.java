package com.ls.asymmetricCrypto;

import com.ls.utils.Utils;

import java.security.*;

import javax.crypto.Cipher;

/**
 *
 */
public class ElGamalwithJCA {

    public static void main(String[] args) throws Exception {

        byte[] input = new byte[]{0x00, 0x01, 0x02};
        System.out.println("Input: " + Utils.bytesToHexString(input));

        // keys generation
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ELGamal"); // generator of the keys
        // initialize with 2048 bits of security, with a secure random source. Takes a lot of time.
        generator.initialize(1024, random);
        KeyPair pair = generator.generateKeyPair(); // generate a pair of PK/SK
        Key pubKey = pair.getPublic(); // method getPublic returns PK
        Key privKey = pair.getPrivate(); // getPrivate SK

        // encryption pass
        Cipher cipher = Cipher.getInstance("ElGamal/None/PKCS1Padding");
        // cipher is for El Gamal with padding done internally by JCA
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random); // init cipher in encrypt mode with PK
        // random is used each time we encrypt to generate randomness for the encryption algorithm
        byte[] cipherText = cipher.doFinal(input);

        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("Decrypted plaintext: " + Utils.bytesToHexString(plainText));

    }

}