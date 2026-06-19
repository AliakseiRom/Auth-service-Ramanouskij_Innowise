package com.innowise.authservice.security.jwt;


import com.innowise.authservice.model.Credential;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-expiration}")
    private long accessExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    private final String TOKEN_TYPE_CLAIM = "tokenType";

    private final String ACCESS_TOKEN_CLAIM = "accessToken";

    private final String REFRESH_TOKEN_CLAIM = "refreshToken";

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateAccessToken(Credential credential) {

        return Jwts.builder()
                .subject(credential.getLogin())
                .claim("userId", credential.getUserId())
                .claim("role", credential.getRole().name())
                .claim(TOKEN_TYPE_CLAIM, ACCESS_TOKEN_CLAIM)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String generateRefreshToken(Credential credential) {

        return Jwts.builder()
                .subject(credential.getLogin())
                .claim(TOKEN_TYPE_CLAIM, REFRESH_TOKEN_CLAIM)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    public Long extractUserId(String token) {
        Claims claims = extractAllClaims(token);

        return claims.get("userId", Long.class);
    }

    public String extractRole(String token) {
        Claims claims = extractAllClaims(token);

        String role = claims.get("role", String.class);

        if (role == null) {
            throw new JwtException("Missing required Claim " + TOKEN_TYPE_CLAIM);
        }

        return role;
    }

    public String extractLogin(String token) {
        return extractAllClaims(token).getSubject();
    }

    public boolean isAccessTokenValid(String token) {
        return isTokenValidByType(token, ACCESS_TOKEN_CLAIM);
    }

    public boolean isRefreshTokenValid(String token) {
        return isTokenValidByType(token, REFRESH_TOKEN_CLAIM);
    }

    public boolean isTokenValidByType(String token, String expectedTokenType) {
        try {

            Claims claims = extractAllClaims(token);

            String actualTokenType = claims.get(TOKEN_TYPE_CLAIM, String.class);
            Date expiration = claims.getExpiration();

            return expectedTokenType.equals(actualTokenType)
                    && expiration != null
                    && expiration.after(new Date());

        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    private Claims extractAllClaims(String token) {

        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}

