package com.appointment.api_gateway.filter;


import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicInteger;

@Component
@Order(-1) // Ensures it runs early
public class RequestLogFilter implements GlobalFilter {

    private final AtomicInteger requestCount = new AtomicInteger(0);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        int currentCount = requestCount.incrementAndGet();
        String path = exchange.getRequest().getURI().getPath();
        System.out.println("➡️ Request #" + currentCount + " received for path: " + path);
        return chain.filter(exchange);
    }
}
