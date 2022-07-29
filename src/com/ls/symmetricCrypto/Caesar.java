package com.ls.symmetricCrypto;

import java.security.SecureRandom;
import java.util.Arrays;

public class Caesar{

    private char[] letters = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z'};

    /**
     * Encrypt with the Caesar encryption scheme the specified message with the given key
     * @param message the message to encrypt
     * @param shift the shift to apply
     * @return the encrypted message
     */
    public static String enc(String message, int shift) {
        char[] chars = message.toCharArray();
        char[] ciphertext = new char[chars.length];
        for (int i=0;i<chars.length;i++) {
            ciphertext[i] = (char)('a'+((chars[i]-'a'+shift) % 26));
        }
        return String.valueOf(ciphertext);
    }

    /**
     * Decrypt with the Caesar encryption scheme the specified ciphertext with the given key
     * @param ciphertext the ciphertext to decrypt
     * @param shift the shift to apply
     * @return the decrypted message
     */
    public static String dec(String ciphertext, int shift) {
        return enc(ciphertext, 26-shift);
    }


    public static void main(String[] args) {

        String messageString = "message";
        byte[] messageBytes = messageString.getBytes();

        // Caesar Cipher
        try{
            SecureRandom r;
            r = SecureRandom.getInstanceStrong();
            int shift = 1 + r.nextInt(25);

            String ciphertext = Caesar.enc(messageString, shift);
            String decrypted = Caesar.dec(ciphertext, shift);

            System.out.println("-> Caesar Encryption");
            System.out.println("Message String: " + messageString);
            System.out.println("Shift value: " + shift);
            System.out.println("Ciphertext String: " + ciphertext);
            System.out.println("Decrypted String: " + decrypted);
            System.out.println();

        }catch (Exception e){
            e.printStackTrace();
        }

        // Caesar Cipher attack
        try{
            SecureRandom r;
            r = SecureRandom.getInstanceStrong();
            int shift = 1 + r.nextInt(25);

            String rigthMessage = "paolo";
            String otherMessage = "zebra";

            String ciphertext = Caesar.enc(rigthMessage, shift);

            System.out.println("-> Caesar Encryption Attack");
            System.out.println("Messages proposed to the Attacker: [" + rigthMessage + "] " + otherMessage);
            System.out.println("Attacker answer: " + new CaesarAttacker(rigthMessage, otherMessage).attack(ciphertext));
            System.out.println();

        }catch (Exception e){
            e.printStackTrace();
        }

    }

}
