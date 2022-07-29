package com.ls.numberTheory;

import java.math.BigInteger;
import java.security.*;

public class DensityPrimes {

    public static void main(String[] args) {

        long c = 0;

		// count the prime numbers until to 2^16
        for (long i = 1; i < 256 * 256; i++) {
            BigInteger a = BigInteger.valueOf(i);
            if (a.isProbablePrime(20))
				c++;
        }

		// compute 2^16 / log2(2^16)
        BigInteger d = BigInteger.valueOf(2);
        d = d.pow(16);
        float D = d.floatValue() / 16;

        System.out.println("Number of primes found: " + c + "\nn/logn: " + D);

    }
}


