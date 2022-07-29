package com.ls.certificates;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.util.concurrent.TimeUnit;


public class SSLServerWithClientAuth extends SSLServer {

    public static void main(String[] args) throws Exception {
        // this server is identical to SSLServer.java except that it invokes setNeedClientAuth to true
        SSLServerSocketFactory fact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket sSock = (SSLServerSocket) fact.createServerSocket(4000);
        sSock.setNeedClientAuth(true); // this is needed to allow Client Authentication
        SSLSocket sslSock = (SSLSocket) sSock.accept();
        Protocol(sslSock);
    }
}
