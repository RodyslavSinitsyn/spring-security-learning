package org.rsinitsyn.factory;

import org.rsinitsyn.Token;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

public class DefaultAccessTokenFactory implements Function<Token, Token> {

    private Duration tokenTtl = Duration.ofMinutes(3);

    @Override
    public Token apply(Token token) {
        var now = Instant.now();
        return new Token(token.id(), token.subject(), token.authorities().stream()
                .filter(a -> a.startsWith("GRANT_"))
                .map(a -> a.replace("GRANT_", ""))
                .toList(), now, now.plus(tokenTtl));
    }
}
