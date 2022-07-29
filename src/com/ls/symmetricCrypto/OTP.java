package com.ls.symmetricCrypto;

import com.ls.utils.Utils;

import java.security.SecureRandom;

public class OTP {

    /**
     * Encrypt with the One Time Pad encryption scheme the specified message with the given key
     * @param message the message to encrypt
     * @param key the key
     * @return the encrypted message
     * @throws Exception if the length of messages is different from the length of key
     */
    public static byte[] enc(byte[] message, byte[] key) throws Exception {
        if(message.length != key.length)
            throw new Exception("message and key must be of the same length");
        byte[] ciphertext = new byte[message.length];
        for(int i = 0; i < key.length; i++){
            ciphertext[i] = (byte) (message[i] ^ key[i]);
        }
        return ciphertext;
    }

    /**
     * Decrypt with the One Time Pad encryption scheme the specified ciphertext with the given key
     * @param ciphertext the ciphertext to decrypt
     * @param key the key
     * @return the decrypted message
     * @throws Exception if the length of messages is different from the length of key
     */
    public static byte[] dec(byte[] ciphertext, byte[] key) throws Exception {
        return enc(ciphertext, key);
    }

    public static void main(String[] args) {

        String messageString = "message";
        byte[] messageBytes = messageString.getBytes();

        // OTP
        try {
            // usando la periferica random meno sicura e meno random
            // r = new SecureRandom();
            // nella installazione java puoi settare le impostazioni della randomness
            // in linux /random è una periferica più sicuro di ottenere randomness
            SecureRandom r;

            byte[] key = new byte[messageBytes.length];
            r = SecureRandom.getInstanceStrong();
            r.nextBytes(key);

            byte[] ciphertext = OTP.enc(messageBytes, key);
            byte[] decrypted = OTP.dec(ciphertext, key);

            System.out.println("-> OTP Encryption");
            System.out.println("Message bytes: " + Utils.bytesToHexString(messageBytes));
            System.out.println("Key bytes: " + Utils.bytesToHexString(key));
            System.out.println("Ciphertext bytes: " + Utils.bytesToHexString(ciphertext));
            System.out.println("Decrypted bytes: " + Utils.bytesToHexString(decrypted));
            System.out.println();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
