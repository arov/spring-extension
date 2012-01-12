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

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * Entry point for parsing CloudSeal Spring namespace
 */
public class CloudSealNamespaceHandler extends NamespaceHandlerSupport {
    
    private static final String SAML_TAG = "sso";

    private final CloudSealBeanDefinitionParser samlParser;

    public CloudSealNamespaceHandler() {
        samlParser = new CloudSealBeanDefinitionParser();
    }

    CloudSealNamespaceHandler(CloudSealBeanDefinitionParser samlParser) {
        this.samlParser = samlParser;
    }

    @Override
    public void init() {
        registerBeanDefinitionParser(SAML_TAG, samlParser);
    }
}
