package org.rsinitsyn;

import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import jakarta.servlet.http.HttpServletResponse;
import org.rsinitsyn.deserializer.AccessTokenJwsStringDeserializer;
import org.rsinitsyn.deserializer.RefreshTokenJweStringDeserializer;
import org.rsinitsyn.seralizer.AccessTokenJwsStringSerializer;
import org.rsinitsyn.seralizer.RefreshTokenJwtStringSerializer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private final String jwtAccessTokenKey;
    private final String jwtRefreshTokenKey;

    public JwtAuthenticationConfigurer(String jwtAccessTokenKey, String jwtRefreshTokenKey) {
        this.jwtAccessTokenKey = jwtAccessTokenKey;
        this.jwtRefreshTokenKey = jwtRefreshTokenKey;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        var configurer = builder.getConfigurer(CsrfConfigurer.class);
        if (configurer != null) {
            configurer.ignoringRequestMatchers(new AntPathRequestMatcher("/jwt/tokens", "POST"));
        }
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        var requestJwtTokensFilter = new RequestJwtTokensFilter()
                .setAccessTokenStringSerializer(
                        new AccessTokenJwsStringSerializer(new MACSigner(OctetSequenceKey.parse(jwtAccessTokenKey)))
                )
                .setRefreshTokenStringSerializer(
                        new RefreshTokenJwtStringSerializer(new DirectEncrypter(OctetSequenceKey.parse(jwtRefreshTokenKey)))
                );

        var jwtAuthFilter = new AuthenticationFilter(
                builder.getSharedObject(AuthenticationManager.class),
                new JwtAuthenticationConverter(
                        new AccessTokenJwsStringDeserializer(new MACVerifier(OctetSequenceKey.parse(jwtAccessTokenKey))),
                        new RefreshTokenJweStringDeserializer(new DirectDecrypter(OctetSequenceKey.parse(jwtRefreshTokenKey)))
                ));
        jwtAuthFilter.setSuccessHandler((request, response, authentication) -> CsrfFilter.skipRequest(request));
        jwtAuthFilter.setFailureHandler((request, response, exception) -> response.sendError(HttpServletResponse.SC_FORBIDDEN));

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(new TokenAuthenticationUserDetailsService());

        builder.addFilterAfter(requestJwtTokensFilter, ExceptionTranslationFilter.class)
                .addFilterBefore(jwtAuthFilter, CsrfFilter.class)
                .authenticationProvider(authenticationProvider);
    }
}
