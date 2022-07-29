package com.ls.providers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.Security;

public class PrecedenceTest {

	public static void main(String[] args){
		try {
			Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
			System.out.println(cipher.getProvider());
			cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
			System.out.println(cipher.getProvider());
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}

               