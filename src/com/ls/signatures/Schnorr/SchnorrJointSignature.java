package com.ls.signatures.Schnorr;

import com.ls.utils.DLogParams;
import com.ls.utils.Utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static com.ls.signatures.Schnorr.Schnorr.*;
import static com.ls.utils.DLogParams.SetupDLogParams;

public class SchnorrJointSignature {

    /**
     * Compute the joint public key of Schnorr signature using key-homomorphism
     * @param publicKeys list of schnorr public keys
     * @return the joint public key of schnorr
     */
    public static SchnorrPK generateJointPublicKey(List<SchnorrPK> publicKeys){

        BigInteger Y;
        Y = BigInteger.ONE;

        // homomorphism of Schnorr to compute the joint public key
        for(SchnorrPK pk: publicKeys){
            Y = Y.multiply(pk.h).mod(pk.p);
        }

        SchnorrPK pk1 = publicKeys.get(0);

        return new SchnorrPK(pk1.p,pk1.q,pk1.g, Y, pk1.securityparameter);
    }

    /**
     * Compute joint signature for Schnorr signature scheme
     * @param signatures list of Schnorr signatures
     * @param jointPublicKey joint public key of Schnorr
     * @param M the message to be signed
     * @return the joint signature of the message
     */
    public static SchnorrSig generateJointSignature(List<SchnorrSig> signatures, SchnorrPK jointPublicKey, String M){
        BigInteger A,E,Z;

        A = BigInteger.ONE;
        Z = BigInteger.ZERO;

        // homomorphism to generate the joint signature
        for(SchnorrSig sig: signatures){
            A = A.multiply(sig.a).mod(jointPublicKey.p);
            Z = Z.add(sig.z).mod(jointPublicKey.q);
        }

        E = HashToBigInteger(jointPublicKey, A, M);

        return new SchnorrSig(A,E, Z);
    }

    /**
     * Compute the joint A of the Schnorr signature scheme using homomorphism.
     * @param leA all the As to be combined
     * @param p the modulo size (parameter of the group)
     * @return joint A
     */
    public static BigInteger computeJointA(List<BigInteger> leA, BigInteger p){

        BigInteger A = BigInteger.ONE;

        for(BigInteger a : leA){
            A = A.multiply(a).mod(p);
        }
        return A;
    }

    public static void main(String[] args){

        int securityparameter = 64;
        int nSigner = 5;

        String message = "Hi this is a joint signed message";

        // generating signers keys
        List<SchnorrSK> skSigj = new ArrayList<>(nSigner);
        List<SchnorrPK> pkSigj = new ArrayList<>(nSigner);
        DLogParams pqg = SetupDLogParams(securityparameter);
        for(int i=0; i < nSigner; i++){
            SchnorrSK sk = SetupDLogParamsFixed(pqg, securityparameter);
            skSigj.add(sk);
            pkSigj.add(sk.getPK());
        }

        // starting protocols
        List<BigInteger> leR = new ArrayList<>(nSigner); // privates to each signer
        List<BigInteger> leA = new ArrayList<>(nSigner);
        List<SchnorrSig> signatures = new ArrayList<>(nSigner);
        // each authority computes A
        for(int i=0; i < nSigner; i++){
            Utils.Pair<BigInteger, BigInteger> AR = computeA(skSigj.get(i));
            leR.add(AR.t);
            leA.add(AR.u);
        }

        // signer exchanges leA

        // anyone can derive pkSig and A
        SchnorrPK joinedSigPk = SchnorrJointSignature.generateJointPublicKey(pkSigj);
        BigInteger A = SchnorrJointSignature.computeJointA(leA, pkSigj.get(0).getP());

        // each signer produces the partial signatures and publish them
        for(int i=0; i < nSigner; i++){
            signatures.add(Schnorr.Sign(skSigj.get(i), message, A, leR.get(i),joinedSigPk));
        }

        // anyone can derive the joint signature
        SchnorrSig joinedSig = SchnorrJointSignature.generateJointSignature(signatures, joinedSigPk, message); // producing the joint signature of the authorities

        // verification of the signature
        System.out.println(Schnorr.Verify(joinedSig, joinedSigPk, message));

    }

}
