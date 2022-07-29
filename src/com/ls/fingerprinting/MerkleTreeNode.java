package com.ls.fingerprinting;

import java.math.BigInteger;

public class MerkleTreeNode {
    BigInteger value;
    MerkleTreeNode[] sons;

    MerkleTreeNode(BigInteger value) {
        this.sons = new MerkleTreeNode[4];
        this.value = value;
        for (int i = 0; i < 4; i++) this.sons[i] = null;
    }

}