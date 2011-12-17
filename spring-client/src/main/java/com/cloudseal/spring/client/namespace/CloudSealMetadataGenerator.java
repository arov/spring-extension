package com.cloudseal.spring.client.namespace;

import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;

public class CloudSealMetadataGenerator extends MetadataGenerator {

    @Override
    public void generateExtendedMetadata(ExtendedMetadata metadata) {
        super.generateExtendedMetadata(metadata);
        metadata.setIdpDiscoveryEnabled(false);
    }    
    
}
