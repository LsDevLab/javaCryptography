package com.ls.certificates;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import java.io.*;
import java.net.*;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

// similar to SSLClient except that the Protocol sends two BigInteger objects to the Server  and the Server prints them
public class SSLClientBigInteger {

    static void Protocol(Socket cSock) throws Exception {

        OutputStream out = cSock.getOutputStream(); //convert socket object in OutputStream

        BigInteger bigInteger = new BigInteger("321");
        try {
            ObjectOutputStream outputStream = new ObjectOutputStream(out);
            // we use ObjectOutputStream to convert out to an ObjectOutputStream that can write arbitrary objects to the stream
            // as result we can send over the secure connection any object we wish
            outputStream.writeObject(bigInteger);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws Exception {
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault(); // similar to the server except
        // use SSLSocketFactory instead of SSLSocketServerFactory
        SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000); // specify host and port
        cSock.startHandshake(); // this is optional - if you do not request explicitly handshake the handshake
        // will be put in place when you try to use the socket
        Protocol(cSock);
        cSock.close();
    }
}

