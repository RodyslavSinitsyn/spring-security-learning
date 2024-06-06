package org.rsinitsyn;

import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Setter
@Accessors(chain = true)
public class HexConfigurer extends AbstractHttpConfigurer<HexConfigurer, HttpSecurity> {

    private AuthenticationEntryPoint authenticationEntryPoint = ((request, response, authException) -> {
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Hex Authentication");
        response.sendError(HttpStatus.UNAUTHORIZED.value());
    });

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.exceptionHandling(config -> config.authenticationEntryPoint(authenticationEntryPoint));
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        var authenticationManager = builder.getSharedObject(AuthenticationManager.class);

        /* Custom filter with auth logic and security context integration (More complex) */
/*        builder.addFilterBefore(new HexAuthenticationFilter(authenticationManager, authenticationEntryPoint),
                BasicAuthenticationFilter.class);*/

        /* Implement only converter, and use existing AuthenticationFilter (Easy) */
        var authenticationFilter = new AuthenticationFilter(authenticationManager, new HexAuthenticationConverter());
        authenticationFilter.setSuccessHandler((request, response, authentication) -> {});
        authenticationFilter.setFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationEntryPoint));
        builder.addFilterBefore(authenticationFilter, BasicAuthenticationFilter.class);
    }
}
