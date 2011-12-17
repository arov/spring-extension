package com.cloudseal.spring.client.userdetails;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class CloudSealUserDetails implements UserDetails {
    
    private static final long serialVersionUID = 1L;

    private final CloudSealUserAttributes attributes;

    public CloudSealUserDetails(CloudSealUserAttributes attributes) {
        this.attributes = attributes;
    }
    
    public CloudSealUserAttributes getAttributes() {
        return attributes;
    }

    @Override
    public String getUsername() {
        return attributes.getUserName();
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return attributes.getRoles();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
}
