package com.ycore.restroversegateway.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("jwt")
public class JwtConfig {
    private String tokenSecret;

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }
    public String getTokenSecret() {
        return tokenSecret;
    }

}
