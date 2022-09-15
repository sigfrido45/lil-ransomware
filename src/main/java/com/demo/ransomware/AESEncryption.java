package com.demo.ransomware;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESEncryption {

    private static final String GSM_ALGORITHM = "AES/GCM/NoPadding";
    private static AESEncryption instance;
    private Key key;
    private IvParameterSpec initialVector;
    private final String password;
    private final byte[] saltBytes;

    public static AESEncryption getInstance(String password) {
        if (instance == null)
            instance = new AESEncryption(password);
        return instance;
    }

    public byte[] encryptBytes(byte[] content) throws AESException {
        try {
            Cipher cipher = Cipher.getInstance(GSM_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getKey(), getGcmParamSpecification());
            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new AESException(e.getMessage());
        }
    }

    public byte[] decryptBytes(byte[] cipherBytes) throws AESException {
        try {
            Cipher cipher = Cipher.getInstance(GSM_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getKey(), getGcmParamSpecification());
            return cipher.doFinal(cipherBytes);
        } catch (Exception e) {
            throw new AESException(e.getMessage());
        }
    }

    public byte[] decryptBytes(byte[] cipherBytes, byte[] saltBytes, byte[] ivBytes) throws AESException {
        try {
            Cipher cipher = Cipher.getInstance(GSM_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getKey(saltBytes), getGcmParamSpecification(ivBytes));
            return cipher.doFinal(cipherBytes);
        } catch (Exception e) {
            throw new AESException(e.getMessage());
        }
    }

    public String getIVInBase64() {
        return Base64.getEncoder().encodeToString(getInitialVector().getIV());
    }

    public String getSaltBytesInBase64() {
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    private AESEncryption(String password) {
        this.password = password;
        this.saltBytes = generateSecureRandomBytes(8);
    }

    private Key getKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (key == null)
            key = getKeyFromPassword(password, saltBytes);
        return key;
    }


    private Key getKey(byte[] saltBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (key == null)
            key = getKeyFromPassword(password, saltBytes);
        return key;
    }

    private AlgorithmParameterSpec getGcmParamSpecification() {
        return new GCMParameterSpec(128, getInitialVector().getIV());
    }

    private AlgorithmParameterSpec getGcmParamSpecification(byte[] ivBytes) {
        return new GCMParameterSpec(128, ivBytes);
    }

    private IvParameterSpec getInitialVector() {
        if (initialVector == null)
            initialVector = generateInitialVector(96);
        return initialVector;
    }

    private IvParameterSpec generateInitialVector(int byteNum) {
        return new IvParameterSpec(generateSecureRandomBytes(byteNum));
    }

    private Key getKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private byte[] generateSecureRandomBytes(int byteNum) {
        byte[] bytes = new byte[byteNum];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
