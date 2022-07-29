package com.ls.fingerprinting;

import java.math.BigInteger;
import java.security.SecureRandom;

public class MerkleTree {
    public static MerkleTreeNode root;
    public static BigInteger g1, g2, g3, g4, p, q;

    public static void Setup(int securityparameter) {

        SecureRandom sc = new SecureRandom(); // create a secure random source

        do {
            q = BigInteger.probablePrime(securityparameter, sc);
            p = q.multiply(BigInteger.TWO);
            p = p.add(BigInteger.ONE);  // p=2q+1
        } while (!p.isProbablePrime(50));

        BigInteger g = new BigInteger("2");
        // TODO MERKLE TREE
        /*while (ElGamal.isqr(g, p) != 1) {
            g = g.add(BigInteger.ONE);
        }*/

        BigInteger s1 = new BigInteger(securityparameter, sc);
        BigInteger s2 = new BigInteger(securityparameter, sc);
        BigInteger s3 = new BigInteger(securityparameter, sc);
        BigInteger s4 = new BigInteger(securityparameter, sc);

        g1 = g.modPow(s1, p);
        g2 = g.modPow(s2, p);
        g3 = g.modPow(s3, p);
        g4 = g.modPow(s4, p);
    }

    public static void BuildTree(MerkleTreeNode[] leaves, int num, int numinputs) { // num power of two
        BigInteger l1, l2, l3, l4;

        if (num == 1) {
            root = leaves[0];
        } else {
            BigInteger[] hashedleaves = new BigInteger[num / numinputs];
            MerkleTreeNode[] fathers = new MerkleTreeNode[num / numinputs];
            for (int i = 0; i < num / numinputs; i++) {
                int j = i * numinputs;
                l1 = leaves[j].value;
                l2 = leaves[j + 1].value;
                if (numinputs == 2) {
                    if (leaves[j].value.compareTo(q) >= 1) l3 = BigInteger.valueOf(1);
                    else l3 = BigInteger.valueOf(0);
                    if (leaves[j + 1].value.compareTo(q) >= 1) l4 = BigInteger.valueOf(1);
                    else l4 = BigInteger.valueOf(0);
                } else {
                    l3 = leaves[j + 2].value;
                    l4 = leaves[j + 3].value;
                }
                hashedleaves[i] = g1.modPow(l1, p).multiply(g2.modPow(l2, p)).mod(p);
                hashedleaves[i] = hashedleaves[i].multiply(g3.modPow(l3, p)).mod(p);
                hashedleaves[i] = hashedleaves[i].multiply(g4.modPow(l4, p)).mod(p);

                fathers[i] = new MerkleTreeNode(hashedleaves[i]);
                for (int k = 0; k < numinputs; k++)
                    fathers[i].sons[k] = leaves[j + k];
            }
            BuildTree(fathers, num / numinputs, 2);
        }
    }
    public static void BuildTree(MerkleTreeNode[] leaves, int num) {
        BuildTree(leaves, num, 4);
    }

    public static void main(String[] args) {
        Setup(1024);
        int num = 16;
        MerkleTreeNode[] leaves = new MerkleTreeNode[num];

        for (int i = 0; i < num; i++)
            leaves[i] = new MerkleTreeNode(BigInteger.valueOf(i));

        BuildTree(leaves, num);
        System.out.println("p: " + p);
        System.out.println("g1: " + g1);
        System.out.println("g2: " + g2);
        System.out.println("g3: " + g3);
        System.out.println("g4: " + g4);
        System.out.println("root: " + root.value);
    }

}