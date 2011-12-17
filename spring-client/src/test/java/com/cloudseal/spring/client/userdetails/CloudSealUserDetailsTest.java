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

    private CloudSealUserAttributes attributes;

    @Before
    public void prepare() {
        attributes = mock(CloudSealUserAttributes.class);
    }

    @Test
    public void userNameIsTakenFromAttributes() {
        final String userName = "user";
        when(attributes.getUserName()).thenReturn(userName);

        assertThat(new CloudSealUserDetails(attributes).getUsername(), is(userName));
    }

    @Test
    public void passwordIsAlwaysEmpty() {
        assertThat(new CloudSealUserDetails(attributes).getPassword(), is(""));
    }

    @Test
    public void rolesAreTakenFromAttributes() {
        final GrantedAuthority role1 = new GrantedAuthorityImpl("USER");
        final GrantedAuthority role2 = new GrantedAuthorityImpl("ADMIN");
        when(attributes.getRoles()).thenReturn(asList(role1, role2));

        assertThat(new CloudSealUserDetails(attributes).getAuthorities(), hasSameOrder(asList(role1, role2)));
    }

    @Test
    public void credentialsAreNeverExpired() {
        assertThat(new CloudSealUserDetails(attributes).isCredentialsNonExpired(), is(true));
    }

    @Test
    public void userIsAlwaysEnabled() {
        assertThat(new CloudSealUserDetails(attributes).isEnabled(), is(true));
    }

    @Test
    public void acountIsNeverLocked() {
        assertThat(new CloudSealUserDetails(attributes).isAccountNonLocked(), is(true));
    }

    @Test
    public void acountIsNeverExpired() {
        assertThat(new CloudSealUserDetails(attributes).isAccountNonExpired(), is(true));
    }
}
