package com.ls.commitments;

public class Commitment {
    public byte[] commitment;
    public byte[] key;
    public String msg;

    public Commitment(byte[] c, byte[] key, String m) {
        this.commitment = c;
        this.key = key;
        this.msg = m;
    }

}
