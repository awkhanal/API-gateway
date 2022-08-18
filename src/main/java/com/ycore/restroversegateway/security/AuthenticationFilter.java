package com.ycore.restroversegateway.security;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ycore.restroversegateway.models.ErrorResponseDto;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.Objects;


@RefreshScope
@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {


    private final RouteValidator routeValidator;
    private final JwtTokenUtil jwtTokenUtil;



    public AuthenticationFilter(RouteValidator routeValidator, JwtTokenUtil jwtTokenUtil) {
        super(Config.class);
        this.routeValidator = routeValidator;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    ErrorResponseDto error = new ErrorResponseDto(new Date(), HttpStatus.UNAUTHORIZED.value(),
                            HttpStatus.UNAUTHORIZED.getReasonPhrase(), "Missing authorization header");
                    return onError(exchange, error);
                }

                System.out.println(exchange.getPrincipal());


                String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
                try {
                    jwtTokenUtil.validateToken(authHeader);
                }
                catch (Exception ex) {
                    log.error("Error Validating Authentication Header", ex);
                    ErrorResponseDto error = new ErrorResponseDto(new Date(), HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase(), ex.getLocalizedMessage());
                    return onError(exchange, error);
                }
            }
            return chain.filter(exchange);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, ErrorResponseDto error) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        ObjectMapper objectMapper = new ObjectMapper();
        DataBuffer buffer = null;
        try {
            buffer = exchange.getResponse().bufferFactory().wrap(objectMapper.writeValueAsBytes(error));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }


    public static class Config {
    }
}