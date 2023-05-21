package com.example.application.component;

import com.example.application.annotation.EncryptedValue;
import com.example.application.util.DecryptionUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.security.PrivateKey;

@Slf4j
@Component
public class EncryptedValueProcessor implements BeanPostProcessor {

    @Value("${application.private_key}")
    private String privateKeyPath;

    // Fetch encrypted key from remote repository (Mock)
    @Value("${application.encrypted_key}")
    private String encryptedKey;

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) {
        Field[] fields = bean.getClass().getSuperclass().getDeclaredFields();
        for (Field field : fields) {
            if (field.isAnnotationPresent(EncryptedValue.class)) {
                decryptField(bean, field);
            }
        }
        return bean;
    }

    private void decryptField(Object bean, Field field) {
        field.setAccessible(true);
        try {
            String encryptedValue = (String) field.get(bean);
            String decryptedValue = decryptValue(encryptedValue);
            field.set(bean, decryptedValue);
        } catch (IllegalAccessException e) {
            log.error("Failed to decrypt Field. Message: {}", e.getMessage(), e);
        }
    }

    private String decryptValue(String encryptedValue) {
        try {
            PrivateKey privateKey = DecryptionUtil.loadPrivateKey(privateKeyPath);
            String secretKey = DecryptionUtil.decryptRSA(encryptedKey, privateKey);
            return DecryptionUtil.decryptAES(encryptedValue, secretKey);
        } catch (Exception e) {
            log.error("Failed to decrypt value. Message: {}", e.getMessage(), e);
            return null;
        }
    }
}
