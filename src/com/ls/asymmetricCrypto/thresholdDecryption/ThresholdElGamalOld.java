package com.ls.asymmetricCrypto.thresholdDecryption;

import com.ls.asymmetricCrypto.ElGamal;
import com.ls.asymmetricCrypto.ElGamalCT;
import com.ls.asymmetricCrypto.ElGamalPK;
import com.ls.asymmetricCrypto.ElGamalSK;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

// example of Threshold El Gamal 
// Vincenzo Iovino

// THRESHOLD ELGAMAL WITH RANDOM SHARES AND SECRET AS SUM OF THEM
// TO DECRYPT NEED THE SECRET KEYS
public class ThresholdElGamalOld extends ElGamal {

	public static ElGamalSK Setup(ElGamalSK SK) { // computes a partial public key
		// given the public parameters taken as input in SK
		SecureRandom sc = new SecureRandom();
		BigInteger s = new BigInteger(SK.PK.securityparameter,sc); // i-th authority has s_i
		BigInteger h = SK.PK.g.modPow(s, SK.PK.p); // and h_i=g^{s_i}
        ElGamalPK PK = new ElGamalPK(SK.PK.p,SK.PK.q,SK.PK.g,h,SK.PK.securityparameter); //
		// return the partial public key of i-th authority
	    return new ElGamalSK(s,PK);
	}

	public static ElGamalSK SetupParameters(int securityparameter) { 
		// since the authorities should work over the same group Zp* we 
		// need to define a SetupParameters method that  computes the public parameters p,q,g shared
		//  by all authorities.
		// For  compatibility with the our structures we compute but ignore h,s.
		BigInteger p,q,g,h,s;
		SecureRandom sc=new SecureRandom(); 
		
		while(true) {
			q = BigInteger.probablePrime(securityparameter, sc);
			p=q.multiply(BigInteger.TWO);
			p=p.add(BigInteger.ONE);
		if (p.isProbablePrime(50))
			break;
		}

		g=new BigInteger("4");
		/*
		while(true) {

			if (isqr(g,p)==1)break;
			g=g.add(BigInteger.ONE);
		}
		*/
		s=BigInteger.ZERO;
		h=BigInteger.ZERO;

		ElGamalPK PK=new ElGamalPK(p,q,g,h,securityparameter);
		return new ElGamalSK(s,PK);
	}

	public static ElGamalPK AggregatePartialPublicKeys(ElGamalPK PK[]) {
		BigInteger tmp=BigInteger.ONE;
		// the array PK contains the partial public keys of the m-authorities
		// in particular PK[i].h=h_i=g^{s_i}
		for (int i=0;i<PK.length;i++)
			tmp=tmp.multiply(PK[i].h).mod(PK[0].p);
		// here tmp=\Prod_{i=1}^m h_i
		// therefore tmp is the General public key h
		return new ElGamalPK(PK[0].p,PK[0].q,PK[0].g,tmp,PK[0].securityparameter);
	}

    public static ElGamalCT PartialDecrypt(ElGamalCT CT, ElGamalSK SK) {
    	// CT is the ciphertext to decrypt or a ciphertext resulting from a partial decryption
    	// Suppose SK is the key of the i-th authority. Then SK.s is s_i
        BigInteger tmp = CT.C2.modPow(SK.s, SK.PK.p); // tmp=C2^s_i 
        tmp=tmp.modInverse(SK.PK.p);   // tmp=C2^{-s_i}
        BigInteger newC = tmp.multiply(CT.C).mod(SK.PK.p); // newC=C*tmp=(h^r*M)*C2^{-s_i}=h^r*M*g^{-rs_i}
        return new ElGamalCT(newC,CT.C2);
    }

    public static void main(String[] args) throws IOException {
		SecureRandom sc = new SecureRandom();

		ElGamalSK Params=SetupParameters(64); // in real implementation set the security parameter to at least 2048 bits
															  //there is some non-trusted entity that generates the parameters
		// we now suppose there are 3 authorities
		ElGamalSK []SK=new ElGamalSK[3];

		for (int i=0;i<3;i++) {
			SK[i]=Setup(Params); // we assume we have m-authorities and they use the parameters generated
			// before to compute 3 partial secret key.
			// Sk[i].s=s_i
			// SK[i].PK.h=h_i=g^s_i
			System.out.println("Setup for "+i+"-th authority:");
			System.out.println("partial secret-key = " + SK[i].s);
			System.out.println("partial public-key = " + SK[i].PK.h);
			System.out.println("p = " + SK[i].PK.p);
			System.out.println("q = " + SK[i].PK.q);
			System.out.println("g = " + SK[i].PK.g);
		  }

		ElGamalPK []PartialPK=new ElGamalPK[3];

		for (int i=0;i<3;i++)
			PartialPK[i]=SK[i].PK;

		ElGamalPK PK = AggregatePartialPublicKeys(PartialPK);
		// from the 3 partial public-keys SK[i].PK=h_i compute
		// the general public-key PK=\prod_{i=1}^3 h_i=h

		BigInteger M;
		M = new BigInteger(Params.PK.securityparameter,sc);

		System.out.println("plaintext to encrypt with threshold El Gamal = " + M);
		ElGamalCT CT = Encrypt(PK,M); // encrypt M in CT
		ElGamalCT PartialDecCT = CT;

		for (int i=0;i<2;i++)
			PartialDecCT=PartialDecrypt(PartialDecCT,SK[i]);

		// the first 2 authorities  use PartialDecrypt to decrypt partial ciphertexts with respect to their partial secret-keys
		BigInteger D = Decrypt(PartialDecCT,SK[2]); // finally the third authority
		// uses the standard decryption procedure to recover the message
		System.out.println("decrypted plaintext with threshold El Gamal = " + D+"\n"); // it should print the same integer as before
    }

}