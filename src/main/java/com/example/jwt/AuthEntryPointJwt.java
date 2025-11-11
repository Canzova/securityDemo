package com.example.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.awt.*;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

// This will be used when an unauthenticated user tries to access a protected resource
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {
    private static Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        logger.error("Unauthorized Error : {}", authException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);  // Converting response into json but why ? where to use this ?
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // Setting the status code as unauthorized 401

        // if this map is declared as final then how can we modify it ? why are we not putting response.setContent into it if we have converted it into json ?
        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("path", request.getServletPath());

        // What is this ?
        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);

    }
}
