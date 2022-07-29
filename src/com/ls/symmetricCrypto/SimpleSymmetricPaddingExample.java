package com.ls.symmetricCrypto;

import com.ls.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SimpleSymmetricPaddingExample {

	public static void main(String[] args) throws Exception {

		byte[] input = new byte[] {
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,0x11,0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,0x11 };

		System.out.println("input : " + Utils.bytesToHexString(input) + " bytes: " + input.length);

		byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,0x34 };
		// note: the key is of 16 bytes but the input is larger so there is padding until the next multiple of 16 bytes.
		// Try out this examples of input array of different lengths (just add entry to the array)
		// and in particular try it out with arrays of length exactly a multiple of
		// 16 bytes (16,32,48,...) to verify that padding is always done.

		System.out.println("key bytes : " + keyBytes.length);

		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
		int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
		ctLength += cipher.doFinal(cipherText, ctLength);
		System.out.println("cipherText: " + Utils.bytesToHexString(cipherText) + " bytes: " + ctLength);

		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
		int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);
		System.out.println("plain : " + Utils.bytesToHexString(plainText) + " bytes: " + ptLength + " " + plainText.length);
		// note: ptLength will be 42 when the input is of 42 bytes but plainText.length is 48 bytes
		// this is because plainText array was allocated of size cipher.getOutputSize(ctLength)=48
		// 48 is the length of the ciphertext that internally uses PKCS7 Padding
		// when the ciphertext is decrypted the part of the plainText array beyond ptLength (the actual length of the input)
		// are not touched by the decryption procedure (they contain the same bytes as before running decryption).

		// here we show the internal padding used for the ciphertext in mode PKCS7
		Cipher cipher_nopad = Cipher.getInstance("AES/ECB/NoPadding");
		cipher_nopad.init(Cipher.DECRYPT_MODE, key);
		plainText = new byte[cipher_nopad.getOutputSize(ctLength)];
		ptLength = cipher_nopad.update(cipherText, 0, ctLength, plainText, 0);
		ptLength += cipher_nopad.doFinal(plainText, ptLength);
		System.out.println("plain : " + Utils.bytesToHexString(plainText) + " bytes: " + ptLength + " " + plainText.length);

	}
}