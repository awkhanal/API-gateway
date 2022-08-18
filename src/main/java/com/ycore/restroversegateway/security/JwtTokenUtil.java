package com.ycore.restroversegateway.security;

import com.ycore.restroversegateway.configuration.JwtConfig;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenUtil {

    private final JwtConfig config;

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);


    public JwtTokenUtil(JwtConfig config) {
        this.config = config;
    }

    public void validateToken(String authHeader) throws SignatureException, MalformedJwtException, ExpiredJwtException,
             UnsupportedJwtException, IllegalArgumentException
    {

        String[] parts = authHeader.split(" ");

        if (parts.length != 2 || !"Bearer".equals(parts[0])) {
            throw new RuntimeException("Incorrect Authentication Structure");
        }

        Jwts.parser().setSigningKey(config.getTokenSecret()).parseClaimsJws(parts[1]);
    }

}
