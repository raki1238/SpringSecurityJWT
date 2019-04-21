package com.auth.security.springsecurejwt.controller;

import com.auth.security.springsecurejwt.model.AuthenticationToken;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping("/token")
public class TokenController {

    public static final long EXPIRATION_SECONDS = 60;
    private static final String SECURITY_KEY = "1@34$7juiasd(8";

    @PostMapping
    public AuthenticationToken generate(@RequestHeader("clientTxt") String clientTxt,
                                        @RequestHeader("clientId") String clientId){
        return new AuthenticationToken(Jwts.builder().setSubject(clientTxt)
                .claim("role", "USER, ADMIN")
                .claim("Id", clientId)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_SECONDS * 1000))
                .signWith(SignatureAlgorithm.HS512, SECURITY_KEY)
                .compact()
        );
    }
}
