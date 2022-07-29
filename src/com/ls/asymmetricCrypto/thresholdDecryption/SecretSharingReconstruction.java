package com.ls.asymmetricCrypto.thresholdDecryption;

import com.ls.utils.Utils;

import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.*;
import java.net.*;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SecretSharingReconstruction {

    static byte[] Protocol(Socket sSock) throws Exception {
        InputStream in = sSock.getInputStream();
        byte[] share = new byte[16];
        try {
            ObjectInputStream objectIn;
            objectIn = new ObjectInputStream(in);
            share = (byte[]) objectIn.readObject();
            sSock.close(); // close connection
        } catch (Exception e) {
            e.printStackTrace();
        }
        return share;
    }

    public static void main(String[] args) throws Exception {
        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        SSLServerSocket sSock;
        SSLSocket[] sslSock = new SSLSocket[3];
        sSock = (SSLServerSocket) sockfact.createServerSocket(4001); // bind to port 4001
        byte[][] secretshares = new byte[3][16];
        byte[] secret = new byte[16];

        for (int i = 0; i < 3; i++) {
            sslSock[i] = (SSLSocket) sSock.accept(); // accept connections
            System.out.println("new connection\n");
            secretshares[i] = Protocol(sslSock[i]);
            sslSock[i].close();
            System.out.println("SecretShare received from  client" + i + " " + Utils.bytesToHexString(secretshares[i]));
        }
        for (int i = 0; i < secret.length; i++)
            for (int j = 0; j < 3; j++) secret[i] = (byte) (secret[i] ^ secretshares[j][i]);
        System.out.println("Reconstructed secret " + Utils.bytesToHexString(secret));

    }

}


