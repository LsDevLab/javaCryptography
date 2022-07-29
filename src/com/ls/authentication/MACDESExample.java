package com.ls.authentication;

import com.ls.utils.Utils;

import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CBC-MAC with DES
 */
public class MACDESExample {

    public static void main(String[] args) throws Exception {

        String input = "00000000";

        Mac mac = Mac.getInstance("DES", "BC"); // not reccomended, use AES
        byte[] macKeyBytes = new byte[]{ // recall that the key should be selected at random and not in this way!!!
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };

        Key macKey = new SecretKeySpec(macKeyBytes, "DES");
        System.out.println("input : " + input);
        byte[] tag = new byte[mac.getMacLength()];
        mac.init(macKey);
        mac.update(input.getBytes());
        tag = mac.doFinal();
        System.out.println("tag: " + Utils.bytesToHexString(tag));

    }
}
