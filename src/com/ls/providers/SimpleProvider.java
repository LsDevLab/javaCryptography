package com.ls.providers;

import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
* with this code we test whether the Bouncy Castle or the SUN provider is
* installed.
*/

public class SimpleProvider {

    public static void main(String[] args){

        String providerName = "BC"; // change this to SUN to test if the standard SUN provider is installed

        // for IDEs like IntelliJ
        Security.addProvider(new BouncyCastleProvider());

        if (Security.getProvider(providerName) == null)
            System.out.println(providerName + " provider not installed");
        else
            System.out.println(providerName + " is installed.");


    }

}
                  