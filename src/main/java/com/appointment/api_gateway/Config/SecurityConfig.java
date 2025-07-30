package com.appointment.api_gateway.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/user/login", "/user/register").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(new CustomJwtConverter())
                                .decoder(customJwtDecoder())
                        )
                )
                .build();
    }

    @Bean
    public ReactiveJwtDecoder customJwtDecoder() {
        return token -> {
            String kid = extractKidFromToken(token);
            PublicKey publicKey = PublicKeyResolver.get(kid); // fetch from your own map/cache/service
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return Mono.just(new Jwt(token, null, null, Map.of("alg", "RS256"), claims));
        };
    }

    private String extractKidFromToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Invalid JWT token");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        return new JSONObject(headerJson).getString("kid");
    }
}
