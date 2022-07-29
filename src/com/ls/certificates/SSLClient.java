package com.ls.certificates;

import com.ls.utils.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.concurrent.TimeUnit;


public class SSLClient {
    public static String s = "Client\n";

    // note that the SSLSocket object is converted in a standard Socket object and henceforth we can work as for standard Java sockets
    static void Protocol(Socket cSock) throws Exception {
        OutputStream out = cSock.getOutputStream();
        InputStream in = cSock.getInputStream();
        // henceforth the client can send a byte array X to the server just writing  with out.write(X)
        // and can read a byte c from the server with c=in.read()
        // in this specific protocol the Client first sends the string "Client" to the Server and receives the string "Server" from the Server and prints it
        // The server sends back the string received to the Client, so the Server will send to the Client the string "Client" and the Client prints it
        // so in the end the Client will print ServerClient
        // The protocol is stupid and serves only to demonstrate how to read and write on secure sockets
        out.write(s.getBytes());
        int ch = 0;
        while ((ch = in.read()) != '\n') {
            System.out.print((char) ch);
            TimeUnit.SECONDS.sleep(1);
        }
        System.out.println((char) ch);
    }

    public static void main(String[] args) throws Exception {
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault(); // similar to the server except
        // use SSLSocketFactory instead of SSLSocketServerFactory
        SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000); // specify host and port
        cSock.startHandshake(); // this is optional - if you do not request explicitly handshake the handshake
        // will be put in place when you try to use the socket
        // henceforth sslSock can be used to read and write on the socket - see the Protocol procedure
        // notice that from this proint the code of the Server and Client is identical - both can read and write using the same oject
        // you could replace Protocol with your own protocol
        Protocol(cSock);
    }
}

