package com.ls.asymmetricCrypto.thresholdDecryption;

import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.*;
import java.net.*;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.KeyStore;

public class Shamir1outof3Participant implements java.io.Serializable {
    static void Protocol2(Socket cSock, BigInteger share) throws Exception {
        OutputStream out = cSock.getOutputStream();
        try {
            ObjectOutputStream outputStream;
            outputStream = new ObjectOutputStream(out);
            outputStream.writeObject(share);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static BigInteger Protocol1(Socket cSock) throws Exception {
        InputStream in = cSock.getInputStream();
        BigInteger share = BigInteger.ONE;
        try {
            ObjectInputStream inputStream;
            inputStream = new ObjectInputStream(in);
            share = (BigInteger) inputStream.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return share;
    }

    // this is the participant in the (1,3)-Shamir SS
    public static void main(String[] args) throws Exception {
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000);
        cSock.startHandshake();
        BigInteger secretshare = Protocol1(cSock);  // receive share from server
        System.out.println("Secret share received: " + secretshare);
        cSock.close();

        if (args[0].equals("1")) { // the participant takes as input 1 or 0. If the input is 1 then the partcipant partcipates in the reconstruction and connects to the Reconstruction Server and sends it the share
            System.out.println("Secret share sent for reconstruction: " + secretshare);
            cSock = (SSLSocket) sockfact.createSocket("localhost", 4001);  // connect to the Reconstruction Server that is listening on port 4001
            Protocol2(cSock, secretshare);  // send it the share
            cSock.close();
        }

    }

}


