package com.example.securityDemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

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
}
