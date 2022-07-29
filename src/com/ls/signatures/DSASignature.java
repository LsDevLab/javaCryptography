package com.ls.signatures;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class DSASignature {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA"); // generate a Key Pair Generator KeyGen for the ECDSA signature scheme
        // you can also use DSA (that will use multiplicative groups rather than elliptic curves) or other types of signatures

        keyGen.initialize(256, new SecureRandom()); // // Inizialize KeyGen with a secure random source and 256 bits of security
        // in the case you use DSA or other types of signatures the bit sizes could be different
        // for example you should set sizes at least 2048 for DSA

        // keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());  use this if you want to use ECDSA with the elliptic curve used by Bitcoin
        // notice that Bitcoin uses ECDSA with this curve but performs a DOUBLE hash before signing - so you would need a further hash to compute and verify Bitcoin signatures

        KeyPair K = keyGen.generateKeyPair(); // Recall that in signatures there is a pair of public- and private- keys.
        // Use the key generator object KeyGen to generate an actual pair K of the type KeyPair.
        // K.getPrivate() gives the secret-key and K.getPublic() gives the public-key and are resp. of the abstract type
        // PrivateKey and PublicKey

        Signature signature = Signature.getInstance("SHA256withECDSA"); // use the factory method to create an instance of Signature for the ECDSA algorithm
        // The signature algorithms follow the Hash+Sign paradigm, that is a message is first possibly hashed using a CRHF and then is signed
        // So, there are different versions of the ECDSA/DSA algorithms depending on the hash function used
        // (or NonewithECDSA in case of no hashing+ECDSA). For instance SHA1withECDSA uses SHA1 in combination with ECDSA.

        // generate a signature
        signature.initSign(K.getPrivate(), new SecureRandom()); // initialize signature for sign with private key K.getPrivate() and a secure random source
        byte[] message = new byte[]{(byte) 'c', (byte) 'i', (byte) 'a', (byte) 'o'}; // this is the message to sign - a byte array
        signature.update(message); // similarly to Cipher/MessageDigest etc. the computation of the signature is done by first using the update method and then
        // applying the sign method.
        byte[] sigBytes = signature.sign(); // sigBytes=S(SK,M'=H(M))
        // verify signature
        // we create another instance of Signature to simulate a verifier that is possibly on another machine and does NOT have the secret-key
        Signature signature2 = Signature.getInstance("SHA256withECDSA");
        signature2.initVerify(K.getPublic()); // initialize signature2 for verification
        // note that when a signature is initialized for sig, the secret-key and a random source are needed
        // whereas for verification the verifier only knows the public-key and
        // the verification algorithms are deterministic

        /*
         * if you change signature2 to be an instance of Signature for NONEwithECDSA the signature will not verify since it was signed after being first hashed with SHA256.
         * In that case, to make the signature verified, you need to first hash the message. Change the generation of signature2 to
         * Signature           signature2 = Signature.getInstance("NONEwithECDSA"); and uncomment what follows to try it.
         * */
        byte[] message2 = new byte[]{(byte) 'c', (byte) 'i', (byte) 'a', (byte) 'o'};
        
        /*
         MessageDigest h=MessageDigest.getInstance("SHA256");
         h.update(message);
         message=h.digest();
         // sigBytes=SHA256withECDSA.Sign(SK,M)=NONEECDSA.Sign(SK,H(M))
         //NONEwithECDSA.Verify(PK,H(M))= SHA256ECDSA.Verify(PK,M)
        */

        signature2.update(message2); // for verification use update+verify methods, first calling update with the message and the calling verify with the signature
        if (signature2.verify(sigBytes)) // returns 1 iff the verification succeeds
        {
            System.out.println("signature verification succeeded.");
        } else {
            System.out.println("signature verification failed.");
        }
    }
}