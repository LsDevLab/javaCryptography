package com.ls.certificates;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.util.concurrent.TimeUnit;

public class SSLServer {
    public static String s = "Server";
    // note that the SSLSocket object is converted in a standard Socket object and henceforth we can work as for standard Java sockets

    static void Protocol(Socket sSock) throws Exception {
        System.out.println("session started.");

        InputStream in = sSock.getInputStream(); // convert the socket to input and output stream
        OutputStream out = sSock.getOutputStream();
        // henceforth the server can send a byte array X to the server just writing  with out.write(X)
        // and can read a byte c from the server with c=in.read()
        // in this specific protocol the Client first sends the string "Client" to the Server and receives the string "Server" from the Server and prints it
        // The server sends back the string received to the Client, so the Server will send to the Client the string "Client" and the Client prints it
        // so in the end the Client will print ServerClient
        // The protocol is stupid and serves only to demonstrate how to read and write on secure sockets
        out.write(s.getBytes());
        int ch = 0;
        while ((ch = in.read()) != '\n') {
            TimeUnit.SECONDS.sleep(1);
            out.write(ch);
        }
        out.write('\n');
        sSock.close(); // close connection
        System.out.println("session closed.");
    }

    public static void main(String[] args) throws Exception {
        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        // create a factory object to handle server connections initialized with the keystore passed as argument in the commandline (see Slides)
        SSLServerSocket sSock = (SSLServerSocket) sockfact.createServerSocket(4000); // bind to port 4000
        while (true) {
            SSLSocket sslSock = (SSLSocket) sSock.accept(); // accept connections
            System.out.println("new connection\n");
            // henceforth sslSock can be used to read and write on the socket - see the Protocol procedure
            // notice that from this proint the code of the Server and Client is identical - both can read and write using the same oject
            // you could replace Protocol with your own protocol
            Protocol(sslSock);
        }
    }
}

