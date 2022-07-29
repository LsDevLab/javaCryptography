package com.ls.asymmetricCrypto;

import java.math.BigInteger;

// structures for ElGamal Ciphertexts
// Vincenzo Iovino
public class ElGamalCT {
    public BigInteger C, C2;

    public ElGamalCT(BigInteger C, BigInteger C2) {
        this.C = C;
        this.C2 = C2;
    }

    public ElGamalCT(ElGamalCT CT) {
        this.C = CT.C;
        this.C2 = CT.C2;
    }

}