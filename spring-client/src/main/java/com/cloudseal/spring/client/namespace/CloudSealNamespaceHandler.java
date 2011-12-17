package com.cloudseal.spring.client.namespace;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

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
