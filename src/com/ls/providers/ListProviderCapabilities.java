package com.ls.providers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

/**
 * List the available capabilities for ciphers, key agreement, macs, message
 * digests, signatures and other objects in the SUN or BC or other providers.
 */
public class ListProviderCapabilities
{
    public static void main( String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        for (Object o : provider.keySet()) {
            String entry = (String) o;
            System.out.println(entry);
        }

    }
}