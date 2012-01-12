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

import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * Default SAMLLogoutFilter sends logout request to IDP and then listens for response. 
 * Local logout is performed only when logout response is received. 
 * 
 * We have a different flow - local logout is performed at once, logout request is dispatched to IDP, but it will not answer.
 * Trying to init SAMLLogoutFilter by passing it 2 arrays as constructor arguments in the namespace parser will cause it
 * to actually call another constructor and logoutHandler won't be added, hence this filter was created. 
 */
public class CloudSealSAMLLogoutFilter extends SAMLLogoutFilter {

    public CloudSealSAMLLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler logoutHandler) {
        super(logoutSuccessHandler, new LogoutHandler[] { logoutHandler }, new LogoutHandler[] { logoutHandler });
    }
}
