package com.ls.asymmetricCrypto.thresholdDecryption;

import com.ls.utils.Utils;

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

public class SecretSharingParticipant implements java.io.Serializable {
    static void Protocol2(Socket cSock, byte[] share) throws Exception {
        OutputStream out = cSock.getOutputStream();
        try {
            ObjectOutputStream outputStream;
            outputStream = new ObjectOutputStream(out);
            outputStream.writeObject(share);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static byte[] Protocol1(Socket cSock) throws Exception {
        InputStream in = cSock.getInputStream();
        byte[] share = new byte[16];
        try {
            ObjectInputStream inputStream;
            inputStream = new ObjectInputStream(in);
            share = (byte[]) inputStream.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return share;
    }

    public static void main(String[] args) throws Exception {
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000);
        cSock.startHandshake();
        byte[] secretshare = Protocol1(cSock);
        System.out.println("Secret share received: " + Utils.bytesToHexString(secretshare));
        cSock.close();
        cSock = (SSLSocket) sockfact.createSocket("localhost", 4001);
        Protocol2(cSock, secretshare);
        cSock.close();
    }

}


