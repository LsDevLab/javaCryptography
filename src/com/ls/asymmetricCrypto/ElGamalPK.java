package com.ls.asymmetricCrypto;

import java.math.BigInteger;

//structures for ElGamal public-key
//Vincenzo Iovino
public class ElGamalPK {
    public BigInteger g, h, p, q; // description of the group and public-key h=g^s
    public int securityparameter; // security parameter

    public ElGamalPK(BigInteger p, BigInteger q, BigInteger g, BigInteger h, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.h = h;
        this.securityparameter = securityparameter;
    }

}