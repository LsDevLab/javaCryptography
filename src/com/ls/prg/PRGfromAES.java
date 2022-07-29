package com.ls.prg;

import com.ls.utils.Utils;

import javax.crypto.Cipher;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

/**
 * PRG from AES
 */
public class PRGfromAES {

	public static void main(String[] args) throws Exception {

		int lengthrange = 100; // the length in bytes of the range of the PRG
		byte[] keyBytes = new byte[16];
		byte[] input = new byte[16*lengthrange];

		for (int i=0; i<lengthrange;i++)
			input[16*i] = (byte)i;

		try {
			SecureRandom r = new SecureRandom();
			r.nextBytes(keyBytes);
			System.out.println("key : " + Utils.bytesToHexString(keyBytes));
		} catch(Exception e) {
			e.printStackTrace();
		}
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES256");
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		System.out.println("input : (l=" + input.length+ ") "+Utils.bytesToHexString(input));

		// encryption pass
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
		int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
		ctLength += cipher.doFinal(cipherText, ctLength);
		System.out.println("PRG string: " + Utils.bytesToHexString(cipherText)
				+ " bytes: " + ctLength+" "+cipher.getOutputSize(ctLength));
	}

}