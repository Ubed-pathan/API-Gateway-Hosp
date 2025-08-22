package com.appointment.api_gateway.Config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import java.util.Base64;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final Map<String, PublicKey> publicKeys = new HashMap<>();

    @Value("${USER_SERVICE_PUBLIC_KEY}")
    private String userServicePublicKey;

    @Value("${DOCTOR_SERVICE_PUBLIC_KEY}")
    private String doctorServicePublicKey;

    @Value("${FRONTEND_URL}")
    private String frontendUrl;

//    @Value("${admin.service.public.key}")
//    private String adminServicePublicKey;

    @PostConstruct
    public void loadKeys() throws Exception {
        publicKeys.put("user-service-key", loadPublicKey(userServicePublicKey));
        publicKeys.put("doctor-service-key", loadPublicKey(doctorServicePublicKey));
//        publicKeys.put("admin-service-key", loadPublicKey(adminServicePublicKey));
    }


    private PublicKey loadPublicKey(String base64Key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(corsSpec -> corsSpec.configurationSource(exchange -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(List.of(frontendUrl));
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                    config.setExposedHeaders(List.of("Authorization"));
                    config.setAllowCredentials(true);
                    return config;
                }))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/user/send-otp", "/user/verify-otp","/user/login", "/user/register").permitAll()
                        .pathMatchers("/user/**").hasRole("USER")
                        .pathMatchers("/doctor/**").hasRole("DOCTOR")
                        .pathMatchers("/admin/**").hasRole("ADMIN")
                        .anyExchange().authenticated()
                )
                .securityContextRepository(customSecurityContextRepository())
                .exceptionHandling(exceptionHandlingSpec ->
                        exceptionHandlingSpec
                                .authenticationEntryPoint((exchange, ex) -> {
                                    // Remove WWW-Authenticate header and return 401 with JSON
                                    exchange.getResponse().getHeaders().remove("WWW-Authenticate");
                                    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                                    // Optionally, write a JSON error body:
                                    // byte[] bytes = "{\"error\":\"Unauthorized\"}".getBytes(StandardCharsets.UTF_8);
                                    // exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                                    // return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
                                    return exchange.getResponse().setComplete();
                                })
                )
                .build();
    }



    @Bean
    public ServerSecurityContextRepository customSecurityContextRepository() {
        return new ServerSecurityContextRepository() {
            @Override
            public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
                return Mono.empty(); // Stateless
            }

            @Override
            public Mono<SecurityContext> load(ServerWebExchange exchange) {
                String jwt = extractJwtFromCookies(exchange);

                if (jwt == null) {
                    return Mono.empty();
                }

                try {
                    Claims claims = parseJwt(jwt);
                    String username = claims.getSubject();
                    String role = claims.get("role", String.class); // assuming single role

                    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    if (role != null) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                    }

                    AbstractAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);

                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("X-User-Id", claims.getSubject())
                            .header("X-User-Email", (String) claims.get("email"))
                            .header("X-User-Name", (String) claims.get("userName"))
                            .build();

                    exchange.mutate().request(mutatedRequest).build();

                    return Mono.just(new SecurityContextImpl(auth));

                } catch (Exception e) {
                    return Mono.empty();
                }
            }
        };
    }

    private String extractJwtFromCookies(ServerWebExchange exchange) {
        return Optional.ofNullable(exchange.getRequest().getCookies().getFirst("jwt"))
                .map(cookie -> cookie.getValue())
                .orElse(null);
    }

    private Claims parseJwt(String token) throws Exception {
        String kid = extractKidFromJwtHeader(token);
        PublicKey key = publicKeys.get(kid);
        if (key == null) throw new IllegalArgumentException("Unknown key ID: " + kid);

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String extractKidFromJwtHeader(String token) throws IOException {
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid JWT");

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readTree(headerJson).get("kid").asText();
    }
}
