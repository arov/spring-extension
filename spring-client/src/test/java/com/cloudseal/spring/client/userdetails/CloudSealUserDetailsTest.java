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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;

import static com.cloudseal.spring.client.namespace.IsCollection.hasSameOrder;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CloudSealUserDetailsTest {

    private CloudsealUserAttributes attributes;

    @Before
    public void prepare() {
        attributes = mock(CloudsealUserAttributes.class);
    }

    @Test
    public void userNameIsTakenFromAttributes() {
        final String userName = "user";
        when(attributes.getUserName()).thenReturn(userName);

        assertThat(new CloudsealUserDetails(attributes).getUsername(), is(userName));
    }

    @Test
    public void passwordIsAlwaysEmpty() {
        assertThat(new CloudsealUserDetails(attributes).getPassword(), is(""));
    }

    @Test
    public void rolesAreTakenFromAttributes() {
        final GrantedAuthority role1 = new GrantedAuthorityImpl("USER");
        final GrantedAuthority role2 = new GrantedAuthorityImpl("ADMIN");
        when(attributes.getRoles()).thenReturn(asList(role1, role2));

        assertThat(new CloudsealUserDetails(attributes).getAuthorities(), hasSameOrder(asList(role1, role2)));
    }

    @Test
    public void credentialsAreNeverExpired() {
        assertThat(new CloudsealUserDetails(attributes).isCredentialsNonExpired(), is(true));
    }

    @Test
    public void userIsAlwaysEnabled() {
        assertThat(new CloudsealUserDetails(attributes).isEnabled(), is(true));
    }

    @Test
    public void acountIsNeverLocked() {
        assertThat(new CloudsealUserDetails(attributes).isAccountNonLocked(), is(true));
    }

    @Test
    public void acountIsNeverExpired() {
        assertThat(new CloudsealUserDetails(attributes).isAccountNonExpired(), is(true));
    }
}
