package com.fecd.apigateway.filter;

import com.fecd.apigateway.config.RouterValidator;
import com.fecd.apigateway.services.IJWTService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
    private final IJWTService ijwtService;


    public AuthenticationFilter(IJWTService ijwtService) {
        super(Config.class);
        this.ijwtService = ijwtService;
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse si = exchange.getResponse();
        si.setStatusCode(httpStatus);
        return null;
    }

    private String extractTokenFromRequest(ServerWebExchange exchange) {
        var request = exchange.getRequest();
        String jwtToken = Objects.requireNonNull(request.getHeaders().get(HttpHeaders.AUTHORIZATION)).getFirst();

        if (jwtToken != null && jwtToken.startsWith("Bearer ")) {
            return jwtToken.substring(7);
        }

        if (request.getCookies().containsKey("access_token")) {
            return request.getCookies().get("access_token").getFirst().getValue();
        }

        return null;

    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        boolean headersAuthMissing = !request.getHeaders().containsKey("Authorization");
        boolean cookiesAuthMissing = !request.getCookies().containsKey("access_token"); // TODO check the cookie key that was set

        return headersAuthMissing || cookiesAuthMissing;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            ServerHttpRequest serverRequest = null;
            if (RouterValidator.isSecured.test(request)) {
                if (isAuthMissing(request)) {
                    return onError(exchange, HttpStatus.UNAUTHORIZED);
                }
            }

            String jwtToken = extractTokenFromRequest(exchange);

            if (jwtToken == null) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            if (ijwtService.isExpired(jwtToken)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            serverRequest = exchange.getRequest().mutate().header("User-Id-Request", ijwtService.extractUserIdFromToken(jwtToken).toString()).build();
            return chain.filter(exchange.mutate().request(serverRequest).build());
        };
    }

    public static class Config {
    }

}
