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

import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;

/**
 * We need to override default MetadataGenerator in order to disable idp discovery feature.
 * This feature redirects request to a page where user is able to select from a list of 
 * available idps.
 */
public class CloudSealMetadataGenerator extends MetadataGenerator {

    @Override
    public void generateExtendedMetadata(ExtendedMetadata metadata) {
        super.generateExtendedMetadata(metadata);
        metadata.setIdpDiscoveryEnabled(false);
    }    
    
}
