package com.example.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Controller
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // JWT expiration time in milli seconds
    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    // Getting JWT From Header
    public String getJwtTokenFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header : {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7); // Getting <token> from Bearer <token>
        }
        return null;
    }

    // Generate Token from UserName
    public String generateTokenFromUserName(UserDetails userDetails){
        String userName = userDetails.getUsername();
        return Jwts.builder()
                .subject(userName)
                .issuedAt(new Date())
                .expiration(new Date((new Date().getTime() + jwtExpirationMs)))
                .signWith(key())
                .compact();
    }

    // Getting the userName from Token
    public String getUserNameFromToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    // Getting Signing key
    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret)
        );
    }

    // Validate JWT token
    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("Validate");
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken);

            return true;
        } catch (Exception exception){
            logger.error("Error is : {}", exception.getMessage());
        }
        return false;
    }
}
