/* Copyright 2011 Cloudseal O†
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudseal.spring.client.namespace;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Map;

import org.springframework.core.io.Resource;
import org.springframework.security.saml.key.JKSKeyManager;

/**
 * This key manager implementation is needed to support JKECS storage types (hardcoded in JKSKeyManager)
 */
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
