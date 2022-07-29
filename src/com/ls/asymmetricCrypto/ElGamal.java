package com.ls.asymmetricCrypto;

import java.math.*;
import java.security.*;
import java.io.*;


// example of ElGamal implementation
// Vincenzo Iovino
public class ElGamal {

    public static ElGamalSK Setup(int securityparameter) {
        BigInteger p, q, g, h;
        SecureRandom sc = new SecureRandom(); // create a secure random source

        while (true) {
            q = BigInteger.probablePrime(securityparameter, sc);
            // method probablePrime returns a prime number of length securityparameter
            // using sc as random source
            p = q.multiply(BigInteger.TWO);
            p = p.add(BigInteger.ONE);  // p=2q+1
            if (p.isProbablePrime(50) == true)
                break;   // returns an integer that is prime with prob. 1-2^-50
        }
        // henceforth we have that p and q are both prime numbers and p=2q+1
        // Subgroups of Zp* have order 2,q,2q

        g = new BigInteger("4"); // 4 is quadratic residue so it generates a group of order q
        // g is a generator of the subgroup the QR modulo p
        // in particular g generates q elements where q is prime

        BigInteger s = new BigInteger(securityparameter, sc); // s is the secret-key
        h = g.modPow(s, p); // h=g^s mod p

        ElGamalPK PK = new ElGamalPK(p, q, g, h, securityparameter);

        return new ElGamalSK(s, PK);
    }

    public static ElGamalCT Encrypt(ElGamalPK PK, BigInteger M) {
        SecureRandom sc = new SecureRandom(); // create a secure random source
        BigInteger r = new BigInteger(PK.securityparameter, sc); // choose random r of lenght security parameter
        // C=[h^r*M mod p, g^r mod p].
        BigInteger C = M.multiply(PK.h.modPow(r, PK.p)); // C=M*(h^r mod p)
        C = C.mod(PK.p); // C=C mod p
        BigInteger C2 = PK.g.modPow(r, PK.p);  // C2=g^r mod p
        return new ElGamalCT(C, C2);   // return CT=(C,C2)
    }

    public static ElGamalCT EncryptInTheExponent(ElGamalPK PK, BigInteger m) {
        // identical to Encrypt except that input is an exponent m and encrypts M=g^m mod p
        SecureRandom sc = new SecureRandom();
        BigInteger M = PK.g.modPow(m, PK.p); // M=g^m mod p
        BigInteger r = new BigInteger(PK.securityparameter, sc);
        BigInteger C = M.multiply(PK.h.modPow(r, PK.p)).mod(PK.p);
        BigInteger C2 = PK.g.modPow(r, PK.p);
        return new ElGamalCT(C, C2);
    }

    public static BigInteger Decrypt(ElGamalCT CT, ElGamalSK SK) {
        // C=[C,C2]=[h^r*M mod p, g^r mod p].
        // h=g^s mod p
        BigInteger tmp = CT.C2.modPow(SK.s, SK.PK.p);  // tmp=C2^s mod p
        tmp = tmp.modInverse(SK.PK.p);
        // if tmp and p are BigInteger tmp.modInverse(p) is the integer x s.t. 
        // tmp*x=1 mod p
        // thus tmp=C2^{-s}=g^{-rs} mod p =h^{-r}
        BigInteger M = tmp.multiply(CT.C).mod(SK.PK.p); // M=tmp*C mod p
        return M;
    }

    public static BigInteger DecryptInTheExponent(ElGamalCT CT, ElGamalSK SK) {
        BigInteger tmp = CT.C2.modPow(SK.s, SK.PK.p).modInverse(SK.PK.p);
        BigInteger res = tmp.multiply(CT.C).mod(SK.PK.p);
        // after this step res=g^d for some d in 1,...,q
        BigInteger M = new BigInteger("0");
        while (true) {
            if (SK.PK.g.modPow(M, SK.PK.p).compareTo(res) == 0) return M;
            // if g^M=res stop and return M
            // otherwise M++
            M = M.add(BigInteger.ONE);
        }

    }

    public static ElGamalCT Homomorphism(ElGamalPK PK, ElGamalCT CT1, ElGamalCT CT2) {
        ElGamalCT CT = new ElGamalCT(CT1); // CT=CT1
        CT.C = CT.C.multiply(CT2.C).mod(PK.p);  // CT.C=CT.C*CT2.C mod p
        CT.C2 = CT.C2.multiply(CT2.C2).mod(PK.p); // CT.C2=CT.C2*CT2.C2 mod p
        return CT; // If CT1 encrypts m1 and CT2 encrypts m2 then CT encrypts m1+m2
    }

    public static void main(String[] args) throws IOException {

        SecureRandom sc = new SecureRandom();

        //Test El Gamal Encrypt+Decrypt
        {
            ElGamalSK SK = Setup(64); // in real implementation set security parameter to at least 2048 bits

            System.out.println("Setup for (standard) El Gamal:");
            System.out.println("secret-key = " + SK.s); // print the SK, PK and the group description
            System.out.println("public-key = " + SK.PK.h);
            System.out.println("p = " + SK.PK.p);
            System.out.println("q = " + SK.PK.q);
            System.out.println("g = " + SK.PK.g);

            BigInteger M;
            M = new BigInteger(SK.PK.securityparameter, sc); // Bob encrypts  a random integer M - note: for security we need to guaranteee this integer to be QR modulo p. For this reason
            M = M.mod(SK.PK.p);

            System.out.println("plaintext to encrypt with (standard) El Gamal = " + M);

            ElGamalCT CT = Encrypt(SK.PK, M); // CT encrypts M
            BigInteger D;
            D = Decrypt(CT, SK);
            System.out.println("decrypted plaintext with (standard) El Gamal = " + D + "\n"); // it should print the same integer as before
        }

        // The following code shows an example of homomorphism of Exponential El Gamal

        //Setup
        ElGamalSK SK = Setup(64); // in real implementation set security parameter to at least 2048 bits
        // Setup done by Alice

        System.out.println("Setup for Exponential El Gamal:");
        System.out.println("secret-key = " + SK.s); // print the SK, PK and the group description
        System.out.println("public-key = " + SK.PK.h);
        System.out.println("p = " + SK.PK.p);
        System.out.println("q = " + SK.PK.q);
        System.out.println("g = " + SK.PK.g);

        BigInteger M1, M2; // Encryption done by Bob and Charlie
        M1 = new BigInteger("24"); // Bob encrypts 24

        M2 = new BigInteger("14"); // Charlie encrypts 14
        ElGamalCT CT1 = EncryptInTheExponent(SK.PK, M1); // CT1 encrypts 24
        ElGamalCT CT2 = EncryptInTheExponent(SK.PK, M2); // CT2 encrypts 14
        ElGamalCT CTH = Homomorphism(SK.PK, CT1, CT2); // CTH encrypts the sum of the plaintexts in CT1 and CT2 that is 24+14

        // Alice receives CTH and wants to decrypt
        BigInteger D;
        D = DecryptInTheExponent(CTH, SK);
        System.out.println("decrypted plaintext with Exponential El Gamal= " + D); // it should be 38

    }

}