package com.example.config.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptionUtil {

    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";

    public static void generateRSAKeyPair(String publicKeyPath, String privateKeyPath) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048);

        KeyPair keyPair = keyGen.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        savePublicKey(publicKey, publicKeyPath);

        PrivateKey privateKey = keyPair.getPrivate();
        savePrivateKey(privateKey, privateKeyPath);
    }

    public static void savePublicKey(PublicKey publicKey, String filePath) throws Exception {
        byte[] publicKeyBytes = publicKey.getEncoded();
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(publicKeyBytes);
        fos.close();
    }

    public static void savePrivateKey(PrivateKey privateKey, String filePath) throws Exception {
        byte[] privateKeyBytes = privateKey.getEncoded();
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(privateKeyBytes);
        fos.close();
    }

    public static String encryptRSA(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(secretBytes);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static String encryptAES(String plaintext, String secretKey) throws Exception {
        byte[] secretKeyBytes = Base64.getDecoder().decode(secretKey);
        SecretKey key = new SecretKeySpec(secretKeyBytes, AES_ALGORITHM);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] secretBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(secretBytes);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static PublicKey loadPublicKey(String publicKeyFilePath) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFilePath));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
}
