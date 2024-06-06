package org.rsinitsyn;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Authentication filter that uses Hex encoding instead of Base64
 */
@Slf4j
public class HexAuthenticationFilter extends OncePerRequestFilter {

    private SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();

    private SecurityContextRepository securityContextRepository =
            new RequestAttributeSecurityContextRepository();

    private AuthenticationManager authenticationManager;

    private AuthenticationEntryPoint authenticationEntryPoint;

    public HexAuthenticationFilter(AuthenticationManager authenticationManager,
                                   AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        var authenticationRequest = HexAuthUtils.getAuthFromRequest(request);
        if (authenticationRequest != null) {
            try {
                Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
                SecurityContext securityContext = this.securityContextHolderStrategy.createEmptyContext();
                securityContext.setAuthentication(authenticationResult);
                this.securityContextHolderStrategy.setContext(securityContext);
                this.securityContextRepository.saveContext(securityContext, request, response);

            } catch (AuthenticationException e) {
                this.securityContextHolderStrategy.clearContext();
                this.authenticationEntryPoint.commence(request, response, e);
                log.error(e.getMessage(), e);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
