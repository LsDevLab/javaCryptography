package com.ls.asymmetricCrypto.thresholdDecryption.thresholdElGamal;

import com.ls.utils.DLogParams;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collection;

import static com.ls.utils.DLogParams.SetupDLogParams;

public class ThresholdElGamal {

	private static final SecureRandom sc = new SecureRandom();

	public static ElGamalCT Encrypt(ElGamalPK PK, BigInteger M) {
		BigInteger r = getR(PK.params.securityparameter);
		// C=[h^r*M mod p, g^r mod p].
		BigInteger C = M.multiply(PK.h.modPow(r, PK.params.p)); // C=M*(h^r mod p)
		C = C.mod(PK.params.p); // C=C mod p
		BigInteger C2 = PK.params.g.modPow(r, PK.params.p);  // C2=g^r mod p
		return new ElGamalCT(C, C2);   // return CT=(C,C2)
	}

	/**
	 * Generate a secret and share it between numOfDecrypters parties using ShamirSecretSharing with
	 * Lagrange coefficients
	 *
	 * @param params the ElGamal parameters
	 * @param numOfDecrypters the number of parties
	 * @param globalPK the global public key
	 * @return a array of secret keys of each party
	 */
	public static ElGamalSK[] LagrangeShamirSecretSharing(ElGamalParams params, int numOfDecrypters, ElGamalPK globalPK) {

		ElGamalSK[] sks = new ElGamalSK[numOfDecrypters];

		BigInteger s = new BigInteger(params.securityparameter,sc).mod(params.q);

		// obtaining the numOfDecrypters shares
		BigInteger[] ai = new BigInteger[numOfDecrypters];
		for (int i = 1; i <= numOfDecrypters - 1; i++) {
			ai[i - 1] = new BigInteger(params.securityparameter,sc).mod(params.q);
		}

		// construct the secret
		for (int j = 0; j < numOfDecrypters; j++) {
			BigInteger sum = BigInteger.ZERO;
			BigInteger xj = BigInteger.valueOf(j + 1);
			for (int i = 1; i < numOfDecrypters; i++) {
				BigInteger iBig = BigInteger.valueOf(i);
				BigInteger aixi = ai[i - 1].multiply(xj.modPow(iBig, params.q)).mod(params.q);
				sum = sum.add(aixi).mod(params.q);
			}
			BigInteger sj = s.add(sum).mod(params.q);
			BigInteger hj = params.g.modPow(sj, params.p);
			ElGamalPK pkAj = new ElGamalPK(hj, params); // associate the public key to the k participant
			sks[j] = new ElGamalSK(sj, pkAj); // associate the secret key to the k participant
		}

		// update the global public key with the common elgamal parameters
		globalPK.params = params;
		globalPK.h = params.g.modPow(s, params.p);

		return sks; //  secret keys with public keys of the participants
	}

	/**
	 * Setup the Threshold ElGamal parameters
	 *
	 * @param securityparameter
	 * @return the parametes
	 */
	public static ElGamalParams SetupParameters(int securityparameter) {
		// since the authorities should work over the same group Zp* we 
		// need to define a SetupParameters method that  computes the public parameters p,q,g shared
		//  by all authorities.
		// For  compatibility with the structures we compute but ignore h,s.
		DLogParams params = SetupDLogParams(securityparameter);
		return new ElGamalParams(params.p, params.q, params.g, securityparameter);
	}

	/**
	 * Threshold decryption using contributes
	 *
	 * @param PK the public key
	 * @param CT the ciphertext to decrypt
	 * @param W the contributes of decryption
	 * @return the plaintext
	 */
    public static BigInteger Decrypt(ElGamalPK PK, ElGamalCT CT, BigInteger[] W) {
		BigInteger wprod = BigInteger.ONE;
		for(int j = 1; j <= W.length; j++){
			BigInteger lambda = BigInteger.ONE; // λ = 1
			for(int l = 1; l <= W.length; l++){ // product from λ = 1 and λ != j to num of coefficients
				if (l != j){
					// λj = l/(l-j) mod q
					BigInteger lj = BigInteger.valueOf(l).subtract(BigInteger.valueOf(j)).mod(PK.params.q);
					BigInteger lambda_l = BigInteger.valueOf(l).multiply(lj.modInverse(PK.params.q)).mod(PK.params.q);
					lambda = lambda.multiply(lambda_l).mod(PK.params.q);
				}
			}
			BigInteger wjlambda = W[j-1].modPow(lambda, PK.params.p); // wj^(lambdaj) mod p
			wprod = wprod.multiply(wjlambda).mod(PK.params.p); // product of previous contribute and current
		}

		return CT.C.multiply(wprod.modInverse(PK.params.p)).mod(PK.params.p); // decrypted message
    }

	/**
	 * Return the product of ciphertexts to use additive homomorphism
	 *
	 * @param pk the public key
	 * @param ciphertexts a collection of ciphertext strings
	 * @return the product of ciphertexts
	 */
	public static ElGamalCT Homomorphism(ElGamalPK pk, Collection<String> ciphertexts){

		ElGamalCT ct = new ElGamalCT();
		for(String ciphertext: ciphertexts){
			ElGamalCT cc = new ElGamalCT(ciphertext);

			ct.C = ct.C.multiply(cc.C).mod(pk.params.p);
			ct.C2 = ct.C2.multiply(cc.C2).mod(pk.params.p);
		}

		return ct;
	}

	/**
	 * Encrypt message m using the given public key
	 *
	 * @param PK the public key
	 * @param m the message
	 * @param r the randomness
	 * @return the resulting ciphertext
	 */
	public static ElGamalCT EncryptInTheExponent(ElGamalPK PK, BigInteger m, BigInteger r) {
		// identical to Encrypt except that input is an exponent m and encrypts M=g^m mod p
		BigInteger M = PK.params.g.modPow(m, PK.params.p); // M=g^m mod p
		BigInteger C = M.multiply(PK.h.modPow(r, PK.params.p)).mod(PK.params.p);
		BigInteger C2 = PK.params.g.modPow(r, PK.params.p);
		return new ElGamalCT(C, C2);
	}

	/**
	 * @param secParam
	 * @return a secure random big integer of secParam bits
	 */
	public static BigInteger getR(int secParam){
		return new BigInteger(secParam, sc);
	}

	public static void main(String[] args) throws IOException {

		int na = 3;

		ElGamalParams params = SetupParameters(64); // in real implementation set the security parameter to at least 2048 bits
		//there is some non-trusted entity that generates the parameters

		//ElGamalSK [] skAj = new ElGamalSK[na];
		//skAj[0] = Setup(64);
		// we now suppose there are 3 authorities
		ElGamalPK pkA = new ElGamalPK();
		ElGamalSK [] skAj = LagrangeShamirSecretSharing(params, na, pkA);

		//ElGamalParams params = skAj[0].PK.params;

		ElGamalPK[] pkAj = new ElGamalPK[na];
		for (int i=0;i<na;i++)
			pkAj[i] = skAj[i].getPK();

		System.out.println("global pk " + pkA.h);

		for (int i=0;i<na;i++) {
			//SK[i]=Setup(Params); // we assume we have m-authorities and they use the parameters generated
			// before to compute na partial secret key.
			// Sk[i].s=s_i
			// SK[i].PK.h=h_i=g^s_i
			System.out.println("Setup for "+i+"-th authority:");
			System.out.println("partial secret-key = " + skAj[i].getS());
			System.out.println("partial public-key = " + skAj[i].getPK().h);
			System.out.println("p = " + skAj[i].getPK().params.p);
			System.out.println("q = " + skAj[i].getPK().params.q);
			System.out.println("g = " + skAj[i].getPK().params.g);
		}

		BigInteger M = new BigInteger(params.securityparameter, sc);
		System.out.println("plaintext to encrypt with threshold El Gamal = " + M);

		ElGamalCT c = Encrypt(pkA,M); // encrypt M in CT

		// each auth computes wj
		BigInteger[] W = new BigInteger[na];
		for (int i=0;i<na;i++){
			W[i] = c.C2.modPow(skAj[i].getS(), pkA.params.p);
			//System.out.println("W["+i+"] = " + W[i]);
		}

		BigInteger D = Decrypt(pkA, c, W); // finally the third authority

		// uses the standard decryption procedure to recover the message
		System.out.println("decrypted plaintext with threshold El Gamal = " + D+"\n"); // it should print the same integer as before

		//BigInteger DD = Decrypt(c, skAj[0]);

		//System.out.println("decrypted plaintext with El Gamal = " + DD+"\n"); // it should print the same integer as before


	}


}