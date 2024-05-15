
package org.example.springsecurity.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.example.springsecurity.model.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {


    @Value("${application.security.jwt.signing-key}")
    private String signingKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;


    public UserDetails extractUserDetails(String token) {
        return extractUserDetails(token, Claims::getSubject, Claims::getAudience);
    }

    private UserDetails extractUserDetails(String token, Function<Claims, String> function1, Function<Claims, String> function2) {
        final Claims claims = extractAllClaims(token);
        String username = function1.apply(claims);
        String role = function2.apply(claims);

        return new User(username, role);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateAccessToken(User user) {
        return generateAccessToken(new HashMap<>(), user, jwtExpiration);
    }

    public String generateAccessToken(Map<String, Object> extraClaims, User user, long expiration) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setAudience(user.getRole())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + (expiration * 60 * 1000)))
                .signWith(createSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims extractAllClaims(String token) {

        return Jwts
                .parserBuilder()
                .setSigningKey(createSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key createSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(signingKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
