package com.example.securityDemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class CustomSecurityConfig {

    // Spring boot will have a dataSource for us automatically because in application.properties we have configured h2 db.
    // So Spring knows we are using h2 db and it will automatically create a datasource for us

    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated());

        // Marking the session as stateless
        http.sessionManagement(session->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        //        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        http.headers(headers->
                headers.frameOptions(frameOptions->frameOptions.sameOrigin()));
        http.csrf(csrf->csrf.disable());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("password2"))
                .roles("ADMIN")
                .build();

        // Creating user in db
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);

        return userDetailsManager;

        //return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    // PasswordEncoder is an interface and BCryptPasswordEncoder is an implementation of it which uses Salt
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
