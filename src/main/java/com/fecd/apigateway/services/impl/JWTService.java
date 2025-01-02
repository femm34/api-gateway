package com.fecd.apigateway.services.impl;

import com.fecd.apigateway.services.IJWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JWTService implements IJWTService {
    @Value("${jwt.secret}")
    private String jwtSecret;

    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isExpired(String token) {
        try {
            return this.getClaims(token).getExpiration().before(new Date());
        } catch (Exception ex) {
            return true;
        }
    }

    public Long extractUserIdFromToken(String token) {
        try {
            return Long.parseLong(this.getClaims(token).getSubject());
        } catch (Exception ex) {
            return null;
        }
    }

}
