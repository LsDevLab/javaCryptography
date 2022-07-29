package com.ls.keyDerivation;

import com.ls.utils.Utils;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class PBKDF2 {

    private static int iterations = 100000;

    public static void main(String[] args){

        try {

            SecureRandom random = new SecureRandom();

            byte[] salt = new byte[64];
            random.nextBytes(salt);

            char[] password = "apassword!?".toCharArray();
            System.out.println("Password chars array: " + Utils.charsArrayToString(password));

            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256); // keyLength in bits
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            byte[] hash = skf.generateSecret(spec).getEncoded();
            System.out.println("Key derived from the password: " + Utils.bytesToHexString(hash));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            System.out.println(e.getMessage());
        }

    }

}
