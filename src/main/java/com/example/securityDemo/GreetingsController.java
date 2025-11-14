package com.example.securityDemo;

import com.example.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/hello")
    public String hello(){
        return "Hello!";
    }

    @PreAuthorize(("hasRole('USER')"))
    @GetMapping("/user")
    public String helloUser(){
        return "Hello User!";
    }

    @PreAuthorize(("hasRole('ADMIN')"))
    @GetMapping("/admin")
    public String helloAdmin(){
        return "Hello Admin!";
    }

    @PostMapping("/signin")
    public ResponseEntity<?>authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;  // It represents an authenticated or logged in user object, it has user info like userName,
        // password, roles etc

        try{
            // AuthenticationManager is a build in class which can authenticate user, it takes userName and password
            // as an authentication Object

            // In order to send userName and password as an authentication object we use this class UsernamePasswordAuthenticationToken
            // It is an implementation of Authentication Interface

            // So if the credentials are correct authenticationManager will also populate the user roles
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUserName(),
                            loginRequest.getPassword())
            );
        }

        // If authentication Fails
        catch(AuthenticationException exception){
            Map<String, Object> map = new HashMap<>();
            map.put("error", "Bad Credentials");
            map.put("status", false);

            return new ResponseEntity<Object>(map, HttpStatus.UNAUTHORIZED);
        }

        // Store the authentication object spring security context, so that spring security can identify the user and its roles
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtils.generateTokenFromUserName(userDetails);

        // getAuthorities this returns the roles in an different type, so to convert it into string we are using stream
        List<String>roles = userDetails.getAuthorities().stream()
                .map(item-> item.getAuthority())
                        .collect(Collectors.toList());
        LoginResponse response = new LoginResponse(jwtToken, userDetails.getUsername(), roles);

        return new ResponseEntity<LoginResponse>(response, HttpStatus.OK);
    }
}
