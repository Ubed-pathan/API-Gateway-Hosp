package com.appointment.api_gateway.Config;

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
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${JWT_PUBLIC_KEY_BASE64}")
    private String jwtPublicKeyBase64;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/user/login", "/user/register").permitAll()
                        .anyExchange().authenticated()
                )
                .securityContextRepository(customSecurityContextRepository()) // Custom security context for JWT handling
                .build();
    }

    @Bean
    public ServerSecurityContextRepository customSecurityContextRepository() {
        return new ServerSecurityContextRepository() {
            @Override
            public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
                return Mono.empty(); // Not needed for stateless JWT
            }

            @Override
            public Mono<SecurityContext> load(ServerWebExchange exchange) {
                String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");


                if (authHeader == null || !authHeader.startsWith("jwt ")) {
                    return Mono.empty(); // No token, unauthorized
                }

                String token = authHeader.substring(7); // Extract the token

                try {
                    Claims claims = parseJwt(token); // Parse the JWT with the public key

                    String username = claims.getSubject();
                    List<String> roles = claims.get("roles", List.class);

                    // Convert roles to authorities
                    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    if (roles != null) {
                        for (String role : roles) {
                            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                        }
                    }

                    // Create the Authentication object
                    AbstractAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);

                    // Add user-related information as headers for downstream services
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("X-User-Id", claims.get("userId").toString())
                            .header("X-User-Email", claims.get("email").toString())
                            .build();

                    exchange.mutate().request(mutatedRequest).build(); // Apply the mutated request

                    // Return SecurityContext with Authentication
                    return Mono.just(new SecurityContextImpl(auth));

                } catch (Exception e) {
                    return Mono.empty(); // Invalid or expired token
                }
            }

        };
    }

    private Claims parseJwt(String token) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(jwtPublicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
