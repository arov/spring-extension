package com.cloudseal.spring.client.userdetails;

import org.jetbrains.annotations.Nullable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

public class SAMLUserDetailsServiceAdapter implements SAMLUserDetailsService {
    
    private UserDetailsService userDetailsService;

    @Override
    public UserDetails loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        CloudSealUserAttributes attributes = new CloudSealUserAttributes(credential);
        if (userDetailsService == null) {
            return new CloudSealUserDetails(attributes);
        } else if (CloudSealUserDetailsService.class.isInstance(userDetailsService)) {
            return ((CloudSealUserDetailsService) userDetailsService).loadUserByUsername(attributes);
        }
        return userDetailsService.loadUserByUsername(attributes.getUserName());
    }

    public void setUserDetailsService(@Nullable UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

}
