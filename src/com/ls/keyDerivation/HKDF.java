package com.ls.keyDerivation;

import com.ls.utils.Utils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.Digest;

public class HKDF {

	public static void main(String[] args) {

		Digest hash = new SHA256Digest();
        byte[] ikm = Hex.decode("0b0b0b02090209090d0709090903"); // weak random source
        byte[] salt = Hex.decode("000102030405060708090a0b0c"); // additional randomness (optional)
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9"); // info related to the application

        int l = 400; // expand to a a key of l bytes
        byte[] okm = new byte[l];
        HKDFParameters params = new HKDFParameters(ikm, salt, info);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(hash);
        hkdf.init(params);
        hkdf.generateBytes(okm, 0, l);

        System.out.println(Utils.bytesToHexString(okm)+ "\n");

    }

}

