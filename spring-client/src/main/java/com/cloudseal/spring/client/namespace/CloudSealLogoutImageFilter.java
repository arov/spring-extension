package com.cloudseal.spring.client.namespace;

import java.io.*;
import java.util.Date;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

public class CloudSealLogoutImageFilter implements Filter {

    private static final int DEFAULT_BUFFER_SIZE = 1024;

    static final Logger LOG = LoggerFactory.getLogger(CloudSealLogoutImageFilter.class);
    
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    
    @Override
    public void init(FilterConfig config) throws ServletException {
        logoutHandler.setInvalidateHttpSession(true);
    }
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException,
    ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) req;
        HttpServletResponse httpResponse = (HttpServletResponse) resp;
        logoutHandler.logout(httpRequest, null, null);
        preventCaching(httpResponse);
        InputStream content = new ClassPathResource("successIcon.png").getInputStream();
        writeContent(httpResponse, "image/png", content);
    }
    
    @Override
    public void destroy() {
    }
    
    protected void preventCaching(HttpServletResponse response) {
        Date now = new Date();
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Date", now.getTime());
        response.setDateHeader("Expires", now.getTime() - 86400000L); // one day old   
        response.setHeader("Cache-Control", "no-cache");
        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Cache-Control", "must-revalidate");
    }
    
    public void writeContent(HttpServletResponse response, String contentType, InputStream content) throws IOException {
        response.setBufferSize(DEFAULT_BUFFER_SIZE);
        response.setContentType(contentType);
        
        BufferedInputStream input = null;
        BufferedOutputStream output = null;

        try {
            input = new BufferedInputStream(content, DEFAULT_BUFFER_SIZE);
            output = new BufferedOutputStream(response.getOutputStream(), DEFAULT_BUFFER_SIZE);

            byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            int length = 0;
            while ((length = input.read(buffer)) > 0) {
                output.write(buffer, 0, length);
            }
        } finally {
            output.close();
            input.close();
        }          
    }


}
