package com.fecd.apigateway.config;

import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.List;
import java.util.function.Predicate;

public abstract class RouterValidator {
    public static final List<String> WHITE_LIST = List.of("/api/v1/health/check");

    public static Predicate<ServerHttpRequest> isSecured = serverHttpRequest -> WHITE_LIST.stream().noneMatch(uri -> serverHttpRequest.getURI().getPath().contains(uri));
}
