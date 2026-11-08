package com.ecdat.vulnerable;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Vulnerable Java Cryptographic Service for ECDAT Evaluation.
 */
public class CryptoService {

    public byte[] rsaEncrypt(byte[] data) throws Exception {
        // Planted Artefact 13: RSA in ECB mode with PKCS1Padding (quantum-vulnerable Shor)
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        return cipher.doFinal(data);
    }

    public KeyPair generateDsaKeys() throws Exception {
        // Planted Artefact 14: DSA KeyPair generation (quantum-vulnerable Shor)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    public byte[] computeSha1(byte[] input) throws Exception {
        // Planted Artefact 15: SHA-1 MessageDigest (classically broken)
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(input);
    }

    public byte[] desEncrypt(byte[] data, byte[] keyBytes) throws Exception {
        // Planted Artefact 16: DES with 56-bit key in CBC mode (classically broken)
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        return cipher.doFinal(data);
    }
}
