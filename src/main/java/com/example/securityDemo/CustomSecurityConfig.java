package com.example.securityDemo;

import com.example.jwt.AuthEntryPointJwt;
import com.example.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated());

        // Marking the session as stateless
        http.sessionManagement(session->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        //   http.formLogin(withDefaults());
        //   http.httpBasic(withDefaults()); no need to use this if you are using JWT

        // if there is any sort of exception or if there is any unauthorized request/access use this handler
        http.exceptionHandling(exception->
                exception.authenticationEntryPoint(unauthorizedHandler)
        );

        http.headers(headers->
                headers.frameOptions(frameOptions->frameOptions.sameOrigin()));
        http.csrf(csrf->csrf.disable());

        // Spring Security has many filters, and we have created one our own custom filter which assigns JWTs to users and
        // register them in spring security context with their details like, name, roles, session timeout etc

        // Use this filter before UsernamePasswordAuthenticationFilter
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initUsers(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;

            if (!manager.userExists("user1")) {
                manager.createUser(User.withUsername("user1")
                        .password(passwordEncoder().encode("password1"))
                        .roles("USER")
                        .build());
            }

            if (!manager.userExists("admin")) {
                manager.createUser(User.withUsername("admin")
                        .password(passwordEncoder().encode("password2"))
                        .roles("ADMIN")
                        .build());
            }
        };
    }


    @Bean
    // PasswordEncoder is an interface and BCryptPasswordEncoder is an implementation of it which uses Salt
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    // We are using it with @Autowired in GreetingsController so in order to use it we need to expose it somewhere
    // Spring should be aware of which AuthenticationManager is expected
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }

}
