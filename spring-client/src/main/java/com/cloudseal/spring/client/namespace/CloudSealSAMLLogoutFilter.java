package com.cloudseal.spring.client.namespace;

import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class CloudSealSAMLLogoutFilter extends SAMLLogoutFilter {

    public CloudSealSAMLLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler logoutHandler) {
        super(logoutSuccessHandler, new LogoutHandler[] { logoutHandler }, new LogoutHandler[] { logoutHandler });
    }
}
