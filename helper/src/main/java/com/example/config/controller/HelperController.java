package com.example.config.controller;

import com.example.config.pojo.EncryptData;
import com.example.config.util.EncryptionUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.security.PublicKey;

@Slf4j
@RestController
@RequestMapping()
public class HelperController {

    @Value("${helper.private_key}")
    private String privateKeyPath;

    @Value("${helper.public_key}")
    private String publicKeyPath;

    @PostMapping("/generate/rsa")
    public Boolean generateRSAKey() throws Exception {
        log.info("Generate RSA Key");
        EncryptionUtil.generateRSAKeyPair(publicKeyPath, privateKeyPath);
        return true;
    }

    @PostMapping("/generate/aes")
    public String generateAESKey() throws Exception {
        log.info("Generate AES Key");
        return EncryptionUtil.generateAESKey();
    }

    @PostMapping("/encrypt/aes")
    public String encryptAES(@RequestBody EncryptData data) throws Exception {
        log.info("Encrypt AES");
        return EncryptionUtil.encryptAES(data.getText(), data.getKey());
    }

    @PostMapping("/encrypt/rsa")
    public String encryptRSA(@RequestBody String text) throws Exception {
        log.info("Encrypt AES");
        PublicKey publicKey = EncryptionUtil.loadPublicKey(publicKeyPath);
        return EncryptionUtil.encryptRSA(text, publicKey);
    }
}
