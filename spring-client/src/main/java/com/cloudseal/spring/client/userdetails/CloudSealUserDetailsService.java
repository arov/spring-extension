package com.cloudseal.spring.client.userdetails;

import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface CloudSealUserDetailsService extends UserDetailsService {
    
    UserDetails loadUserByUsername(CloudSealUserAttributes attributes) throws UsernameNotFoundException,
            DataAccessException;
}
