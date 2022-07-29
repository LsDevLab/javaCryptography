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

// SHAMIR (1,3) WITH
public class Shamir1outof3Dealer {
    public static BigInteger q;

    static void Protocol(Socket sSock, BigInteger secretshare) throws Exception {
        OutputStream out = sSock.getOutputStream();
        try {
            ObjectOutputStream objectOut;
            objectOut = new ObjectOutputStream(out);
            objectOut.writeObject(secretshare);
            System.out.println("secretshare sent to client" + " " + secretshare);
            sSock.close(); // close connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // this is the implementation of the dealer of a (1,3)-Shamir SS, that is each subset of 2 participants must recover the secret but any single participant does not.
    // we work in the field Fq and the polynomial is aX+s.
    public static void main(String[] args) throws Exception {
        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        SSLServerSocket sSock;
        SSLSocket[] sslSock = new SSLSocket[3];
        sSock = (SSLServerSocket) sockfact.createServerSocket(4000); // bind to port 4000

        SecureRandom sc = new SecureRandom();

        q = new BigInteger("15152610295263196997"); //  prime of 64 bits
        BigInteger a = (new BigInteger(64, sc)).mod(q); // choose random a in Fq
        BigInteger s = (new BigInteger(64, sc)).mod(q); // s is random in Fq.
        // We have the polynomial p(X)=aX+s
        System.out.println("secret: " + s);
        BigInteger[] secretshares = new BigInteger[3]; // this is the array that will contain the shares to send to each participant

        for (int i = 0; i < 3; i++) {
            secretshares[i] = a.multiply(BigInteger.valueOf(i + 1)).add(s).mod(q); // secretshares[i]=a(i+1)+s mod q
            System.out.println("Secret share no." + i + "= " + secretshares[i]);
        }

        for (int i = 0; i < 3; i++) {
            sslSock[i] = (SSLSocket) sSock.accept(); // accept connections
            System.out.println("new connection\n");
            Protocol(sslSock[i], secretshares[i]);  // send to the i-th client secretshares[i]
        }

    }

}


