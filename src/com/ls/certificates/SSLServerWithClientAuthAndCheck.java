package com.ls.certificates;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;


public class SSLServerWithClientAuthAndCheck extends SSLServer {

    static boolean verifyidentity(SSLSession session) throws SSLPeerUnverifiedException {
        X500Principal id = (X500Principal) session.getPeerPrincipal(); // getPeerPrincipal returns info about the X500Principal of the other peer
        // X500Principal is the field that contains country, Common Name, etc.
        System.out.println("principal: " + id.getName()); // print this info
        return id.getName().equals("CN=localhost,OU=DIEM,O=unisa,C=IT"); // and returns true iff the X500 principal of the client is equal to "CN=localhost,OU=DIEM,O=unisa,C=IT"
    }

    public static void main(String[] args) throws Exception {
        // create a context and set up a socket factory
        SSLServerSocketFactory fact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket sSock = (SSLServerSocket) fact.createServerSocket(4000);
        sSock.setNeedClientAuth(true);
        SSLSocket sslSock = (SSLSocket) sSock.accept();
        sslSock.startHandshake(); // after handshake this server wants to obtain info about the connected client and 1) will print this info and 2) will execute the protocol
        // only with clients having a specific X500Principal
        if (verifyidentity(sslSock.getSession())) // the method getSession returns an object SSLSession that contains info about the SSL Session
        {
            Protocol(sslSock);
        } else System.out.println("Invalid certificate");
    }

}
