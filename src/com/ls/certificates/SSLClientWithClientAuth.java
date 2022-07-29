package com.ls.certificates;

import com.ls.certificates.SSLClient;

import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.concurrent.TimeUnit;


public class SSLClientWithClientAuth extends SSLClient {

    static SSLContext createSSLContext() throws Exception {

        KeyManagerFactory keyFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore clientStore = KeyStore.getInstance("JKS");

        clientStore.load(new FileInputStream("keystore.jks"), "changeit".toCharArray());
        keyFact.init(clientStore, "changeit".toCharArray());

        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");
        // there are two options: one call init with keyFact.getKeyManagers() and in this case it uses the first matching key from keystoreclient.jks
        // or uses MyKeyManager as shown below specifying as first parameter the keystore file, second parameter the password and third the alias that points to the key
        // you want to use.
        //
        //sslContext.init(new X509KeyManager[] {new MyKeyManager("keystore.jks","changeit".toCharArray(),"ssltest") },null, null);
        sslContext.init(keyFact.getKeyManagers(), null, null);

        return sslContext;
    }

    public static void main(String[] args) throws Exception {
        SSLContext sslContext = createSSLContext();
        SSLSocketFactory fact = sslContext.getSocketFactory(); // create the socket from an SSLContext linked to a specific alias in the keystore - this allows the client to authenticate to the server with the private key corresponding to that alias
        SSLSocket cSock = (SSLSocket) fact.createSocket("localhost", 4000);

        Protocol(cSock);
    }
}

