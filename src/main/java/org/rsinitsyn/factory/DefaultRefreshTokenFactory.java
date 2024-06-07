package org.rsinitsyn.factory;

import org.rsinitsyn.Token;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedList;
import java.util.UUID;
import java.util.function.Function;

public class DefaultRefreshTokenFactory implements Function<Authentication, Token> {

    private Duration tokenTtl = Duration.ofDays(1);

    @Override
    public Token apply(Authentication authentication) {
        var authorities = new LinkedList<String>();
        authorities.add("JWT_REFRESH");
        authorities.add("JWT_LOGOUT");
        authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(a -> "GRANT_" + a)
                .forEach(authorities::add);
        var now = Instant.now();
        return new Token(UUID.randomUUID(), authentication.getName(), authorities, now, now.plus(tokenTtl));
    }
}
