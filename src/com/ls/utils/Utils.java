package com.ls.utils;

import java.math.BigInteger;

public class Utils {

    /**
     * @param bytes the bytes to convert
     * @return a hex string representation of the given bytes
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for(byte b: bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * @param chars the chars array to convert
     * @return a hex string representation of the given chars array
     */
    public static String charsArrayToString(char[] chars) {
        StringBuilder sb = new StringBuilder(chars.length);
        for(char c: chars) {
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * @param string the string to convert
     * @return a byte arrays representing the string
     */
    public static byte[] toByteArray(String string){
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++){
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }

    public static int isqr(BigInteger x, BigInteger p) {

        if (x.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.TWO), p).compareTo(BigInteger.ONE) == 0)
            return 1;
        return 0;
    }

    public static class Pair<T, U> {
        public final T t;
        public final U u;

        public Pair(T t, U u) {
            this.t= t;
            this.u= u;
        }
    }

}
