package com.cloudseal.spring.client.namespace;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Map;

import org.springframework.core.io.Resource;
import org.springframework.security.saml.key.JKSKeyManager;

public class CloudSealKeyManagerImpl extends JKSKeyManager {

    public CloudSealKeyManagerImpl(Resource storeFile, String storePass, Map<String, String> passwords,
            String defaultKey, String storeType) {
        super(createKeyStore(storeFile, storePass, storeType), passwords, defaultKey);
    }
    
    protected static KeyStore createKeyStore(Resource storeFile, String storePass, String storeType) {
        InputStream inputStream = null;
        try {
            inputStream = storeFile.getInputStream();
            KeyStore ks = KeyStore.getInstance(storeType);
            ks.load(inputStream, storePass.toCharArray());
            return ks;
        } catch (Exception e) {
            throw new RuntimeException("Error initializing keystore", e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                }
            }
        }
    }
}
