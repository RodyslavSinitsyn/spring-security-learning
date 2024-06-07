package org.rsinitsyn;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.rsinitsyn.factory.DefaultAccessTokenFactory;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.function.Function;

public class RefreshTokenFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/refresh", "POST");

    private Function<Token, Token> accessTokenFactory = new DefaultAccessTokenFactory();
    private Function<Token, String> accessTokenStringSerializer;

    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private ObjectMapper objectMapper = new ObjectMapper();


    public RefreshTokenFilter(Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (requestMatcher.matches(request)) {
            if (securityContextRepository.containsContext(request)) {
                var securityContext = securityContextRepository.loadDeferredContext(request).get();
                if (securityContext != null
                        && securityContext.getAuthentication() instanceof PreAuthenticatedAuthenticationToken
                        && securityContext.getAuthentication().getPrincipal() instanceof TokenUser user
                        && user.getAuthorities().contains(new SimpleGrantedAuthority("JWT_REFRESH"))) {

                    Token accessToken = this.accessTokenFactory.apply(user.getToken());

                    var tokens = new Tokens(
                            accessTokenStringSerializer.apply(accessToken),
                            accessToken.expiresAt().toString(),
                            null, null);

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    objectMapper.writeValue(response.getWriter(), tokens);
                }
            }
            throw new AccessDeniedException("User must be authenticated with JWT");
        }

        filterChain.doFilter(request, response);
    }
}
