package com.ls.utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class AESUtils {

    public static SecretKey genKey(int bitLength, SecureRandom r) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(bitLength, r);
        return generator.generateKey();
    }

    public static IvParameterSpec genCTRIv(SecureRandom r) {
        byte[] ivBytes = new byte[16];
        // initially randomize
        r.nextBytes(ivBytes);
        // set the counter bytes to 0
        for (int i = 0; i != 8; i++) {
            ivBytes[8 + i] = 0;
        }
        return new IvParameterSpec(ivBytes);
    }

}
