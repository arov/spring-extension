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
package com.cloudseal.spring.client.userdetails;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.saml.SAMLCredential;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

public class SAMLUserDetailsServiceAdapterTest {

    private SAMLCredential credential;

    @Before
    public void prepare() {
        credential = mock(SAMLCredential.class);
    }

    @Test
    public void internalImplementationIfNoServiceSet() {
        final UserDetails details = new SAMLUserDetailsServiceAdapter().loadUserBySAML(credential);
        assertThat(details, is(instanceOf(CloudSealUserDetails.class)));
    }

    @Test
    public void internalImplementationIfNullServiceSet() {
        final SAMLUserDetailsServiceAdapter adapter = new SAMLUserDetailsServiceAdapter();
        adapter.setUserDetailsService(null);

        final UserDetails details = adapter.loadUserBySAML(credential);
        assertThat(details, is(instanceOf(CloudSealUserDetails.class)));
    }

    @Test
    public void standardExternalImplementation() {
        final UserDetails details = mock(UserDetails.class);
        final UserDetailsService service = mock(UserDetailsService.class);
        when(service.loadUserByUsername(anyString())).thenReturn(details);

        final SAMLUserDetailsServiceAdapter adapter = new SAMLUserDetailsServiceAdapter();
        adapter.setUserDetailsService(service);

        adapter.loadUserBySAML(credential);
        verify(service, times(1)).loadUserByUsername(anyString());
    }

    @Test
    public void cloudSealExternalImplementation() {
        final UserDetails details = mock(UserDetails.class);
        final CloudSealUserDetailsService service = mock(CloudSealUserDetailsService.class);
        when(service.loadUserByUsername(anyString())).thenReturn(details);
        when(service.loadUserByUsername(any(CloudSealUserAttributes.class))).thenReturn(details);

        final SAMLUserDetailsServiceAdapter adapter = new SAMLUserDetailsServiceAdapter();
        adapter.setUserDetailsService(service);

        adapter.loadUserBySAML(credential);
        verify(service, times(0)).loadUserByUsername(anyString());

        verify(service, times(1)).loadUserByUsername(any(CloudSealUserAttributes.class));
    }
}
