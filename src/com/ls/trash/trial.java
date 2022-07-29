package com.ls.trash;

import java.math.BigInteger;

public class trial {

    public static void main(String[] args){
        BigInteger votes = new BigInteger("47483647");
        BigInteger yes = new BigInteger("47483646");
        BigInteger i = BigInteger.ZERO;
        while (i.compareTo(votes) < 0){
            if (yes.equals(i))
                System.out.println(yes);
            i = i.add(BigInteger.ONE);
        }

    }

}
