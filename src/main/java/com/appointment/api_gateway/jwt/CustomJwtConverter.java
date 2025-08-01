//package com.appointment.api_gateway.jwt;
//
//import com.fasterxml.jackson.databind.util.Converter;
//import io.jsonwebtoken.Jwt;
//import org.springframework.security.authentication.AbstractAuthenticationToken;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
//
//import java.util.Collection;
//import java.util.List;
//import java.util.stream.Collectors;
//
//public class CustomJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {
//    @Override
//    public AbstractAuthenticationToken convert(Jwt jwt) {
//        String username = jwt.getClaim("sub");
//        List<String> roles = jwt.getClaim("roles");
//
//        Collection<GrantedAuthority> authorities = roles != null
//                ? roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList())
//                : List.of();
//
//        return new JwtAuthenticationToken(jwt, authorities, username);
//    }
//}
