package com.example.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

@Component
public class JWTUtil {
    @Value("${spring.security.jwt.key}")
    private String key;
    @Value("${spring.security.jwt.expire}")
    private int expire;

    @Resource
    private StringRedisTemplate redisTemplate;

    public Date expiresAt() {
        var calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire * 24);
        return calendar.getTime();
    }

    public String encode(UserDetails userDetails, int id, String username) {
        Algorithm algorithm = Algorithm.HMAC256(key);

        return JWT
                .create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id", id)
                .withClaim("name", username)
                .withClaim("authorities", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expiresAt())
                .withIssuedAt(new Date())
                .sign(algorithm);
    }


    public DecodedJWT decode(String token) {
        String _token = covertToken(token);
        if (_token == null) {
            return null;
        }

        Algorithm algorithm = Algorithm.HMAC256(key);

        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        try {
            DecodedJWT verify = jwtVerifier.verify(_token);
            Date expiresAt = verify.getExpiresAt();
            // 如果token已经过期，那么返回null;
            return new Date().after(expiresAt) ? null : verify;
        } catch (JWTVerificationException e) {
            return null;
        }

    }

    private String covertToken(String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return null;
        }
        return token.substring(7);
    }

    public UserDetails toUser(DecodedJWT jwt) {
        var claims = jwt.getClaims();

        return User.withUsername(claims.get("name").asString())
                .password("*******")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }

    public Integer toId(DecodedJWT jwt) {
        var claims = jwt.getClaims();
        return claims.get("id").asInt();
    }

    public boolean invalidJWT(String token) {
        var _token = this.covertToken(token);
        if (_token == null) {
            return false;
        }

        var algorithm = Algorithm.HMAC256(key);
        var verifier = JWT.require(algorithm).build();

        try {
            var jwt = verifier.verify(_token);
            String id = jwt.getId();

        } catch (JWTVerificationException e) {
            return false;
        }

    }

    private boolean deleteToken(String uuid,Date expireAt){

    }

    private boolean isExpired(String uuid){
        Boolean hasKey = redisTemplate.hasKey(Const.BLACK_LIST.getName() + uuid);
    }
}
