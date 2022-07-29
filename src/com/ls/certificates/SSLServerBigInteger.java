package com.ls.certificates;

import java.math.BigInteger;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.io.*;
import java.net.*;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.util.concurrent.TimeUnit;

// similar to SSLServer except that the Protocol sends a BigInteger object to the Server  and the Server prints them
public class SSLServerBigInteger {

    static void Protocol(Socket sSock) throws Exception {
        System.out.println("session started.");
        InputStream in = sSock.getInputStream(); // convert the socket to input stream
        try {
            ObjectInputStream objectIn = new ObjectInputStream(in); // we use ObjectInputStream to convert in to an ObjectInputStream that can read arbitrary objects to the stream
            BigInteger bigInteger = (BigInteger) objectIn.readObject();
            System.out.println("We received: " + bigInteger); // we print the BigInteger received - it should print 321 (see the SSLCLientBigInteger)
        } catch (Exception e) {
            e.printStackTrace();
        }
        sSock.close(); // close connection
        System.out.println("session closed.");
    }

    public static void main(String[] args) throws Exception {
        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        // create a factory object to handle server connections initialized with the keystore passed as argument in the commandline
        SSLServerSocket sSock = (SSLServerSocket) sockfact.createServerSocket(4000); // bind to port 4000
        SSLSocket sslSock = (SSLSocket) sSock.accept(); // accept connections
        // sslSock can be used to read and write 
        Protocol(sslSock);
    }
}

