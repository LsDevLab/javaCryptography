package com.ls.asymmetricCrypto.thresholdDecryption;

import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.*;
import java.net.*;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Shamir1outof3Reconstruction {
    public static BigInteger q;

    public static BigInteger Reconstruct(int i1, BigInteger si1, int i2, BigInteger si2) {
        BigInteger Lambdai1, Lambdai2, tmp;

        tmp = BigInteger.valueOf(i2).subtract(BigInteger.valueOf(i1)).modInverse(q);
        tmp = BigInteger.valueOf(i2).multiply(tmp).mod(q);
        Lambdai1 = tmp; //Lambda_{i1}=i2/(i2-i1) mod q - note: the division is modular division, that  is a/b is a*c mod q where c is the inverse of b modulo q

        tmp = BigInteger.valueOf(i1).subtract(BigInteger.valueOf(i2)).modInverse(q);
        tmp = BigInteger.valueOf(i1).multiply(tmp).mod(q);
        Lambdai2 = tmp;
        // symmetrically we compute Lambda_{i2}=i1/(i1-i2) mod q

        BigInteger reconstructedSecret = si1.multiply(Lambdai1).mod(q);
        reconstructedSecret = reconstructedSecret.add(si2.multiply(Lambdai2).mod(q)).mod(q); // si1*Lambda_{i1}+si2*Lambda_{i2} that (see slides) is equal to the secret
        return reconstructedSecret;
    }

    static BigInteger Protocol(Socket sSock) throws Exception {
        InputStream in = sSock.getInputStream();
        BigInteger share = BigInteger.ONE;
        try {
            ObjectInputStream objectIn;
            objectIn = new ObjectInputStream(in);
            share = (BigInteger) objectIn.readObject();
            sSock.close(); // close connection
        } catch (Exception e) {
            e.printStackTrace();
        }
        return share;
    }

    public static void main(String[] args) throws Exception {
        q = new BigInteger("15152610295263196997");

        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        SSLServerSocket sSock;
        SSLSocket[] sslSock = new SSLSocket[3];
        sSock = (SSLServerSocket) sockfact.createServerSocket(4001); // bind to port 4001

        int i1 = Integer.parseInt(args[0]); // the Reconstruction server receives as input two integers corresponding to the two participants
        // from whose shares it reconstructs the secret
        int i2 = Integer.parseInt(args[1]); // i1 (resp. i2) is the index of the first (resp. second) participant

        BigInteger[] secretshares = new BigInteger[3];
        BigInteger secret;

        sslSock[i1 - 1] = (SSLSocket) sSock.accept(); // accept connections
        System.out.println("new connection\n");
        secretshares[i1 - 1] = Protocol(sslSock[i1 - 1]);
        System.out.println("secretshare received from  client" + i1 + " " + secretshares[i1 - 1]);
        sslSock[i1 - 1].close();
        // until this point the Server of Reconstruction received the share from partipant i1 and stored in secretshares[i1-1]

        sslSock[i2 - 1] = (SSLSocket) sSock.accept(); // accept connections
        System.out.println("new connection\n");
        secretshares[i2 - 1] = Protocol(sslSock[i2 - 1]);
        System.out.println("secretshare received from  client" + i2 + " " + secretshares[i2 - 1]);
        sslSock[i2 - 1].close();
        //  the Server of Reconstruction received the i2-share from partipant i2 and stored in secretshares[i2-1]

        secret = Reconstruct(i1, secretshares[i1 - 1], i2, secretshares[i2 - 1]);
        System.out.println("Reconstructed secret " + secret);
    }

}


