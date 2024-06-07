package org.rsinitsyn;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.function.Function;

public class JwtAuthenticationConverter implements AuthenticationConverter {

    private Function<String, Token> accessTokenStringDeserializer;
    private Function<String, Token> refreshTokenStringDeserializer;

    public JwtAuthenticationConverter(Function<String, Token> accessTokenStringDeserializer, Function<String, Token> refreshTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            var tokenValue = authorizationHeader.replace("Bearer ", "");
            var accessToken = accessTokenStringDeserializer.apply(tokenValue);
            if (accessToken != null) {
                return new PreAuthenticatedAuthenticationToken(accessToken, tokenValue);
            }

            var refreshToken = refreshTokenStringDeserializer.apply(tokenValue);
            if (refreshToken != null) {
                return new PreAuthenticatedAuthenticationToken(refreshToken, tokenValue);
            }
        }

        return null;
    }
}
