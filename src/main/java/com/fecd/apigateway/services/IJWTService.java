package com.fecd.apigateway.services;

import io.jsonwebtoken.Claims;

public interface IJWTService {
    Claims getClaims(String token);
    boolean isExpired(String token);
    Long extractUserIdFromToken(String token);
}
