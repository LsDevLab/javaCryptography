package com.ls.symmetricCrypto;

public class CaesarAttacker {

    private String m0, m1;

    public CaesarAttacker(String m0, String m1){
        this.m0 = m0;
        this.m1 = m1;
    }

    public String attack(String ciphertext) throws Exception{
        for(int shift = 1; shift <= 26; shift++){
            String decrypted = Caesar.dec(ciphertext, shift);
            if (decrypted.equals(m0))
                return m0;
            else if (decrypted.equals(m1))
                return m1;
        }
        throw new Exception("The ciphered message is not " + m0 + " neither " + m1);
    }

}
