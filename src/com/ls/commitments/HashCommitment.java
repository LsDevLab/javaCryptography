package com.ls.commitments;

import java.security.SecureRandom;
import java.security.MessageDigest;

public class HashCommitment {
    static SecureRandom r = new SecureRandom();

    public static Commitment genCommitment(String msg) {
        byte[] key = new byte[32];
        HashCommitment.r.nextBytes(key);
        try {
            MessageDigest h = MessageDigest.getInstance("SHA256");
            h.update((new String(key) + msg).getBytes());
            return new Commitment(h.digest(), key, msg);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifyCommitment(byte[] com, String m, byte[] key) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA256");
            h.update((new String(key) + m).getBytes());
            return MessageDigest.isEqual(com, h.digest());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


    public static void main(String[] args) throws Exception {

        // COMMIT
        String m = "YES";
        Commitment c = genCommitment(m);
        // the sender sends c.commitment to the receiver

        // verifyCommitment(c.commitment, EVERYTHING, EVERYTHING) fails

        // DE-COMMIT
        // sender sends key, m to receiver
        // receiver can verify the message was the one that the sender told him
        System.out.println(verifyCommitment(c.commitment, m, c.key));

    }

}
