package org.rsinitsyn;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.rsinitsyn.factory.DefaultAccessTokenFactory;
import org.rsinitsyn.factory.DefaultRefreshTokenFactory;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Function;

@Setter
@Accessors(chain = true)
public class RequestJwtTokensFilter extends OncePerRequestFilter {

    private AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/tokens", "POST");
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private Function<Authentication, Token> refreshTokenFactory = new DefaultRefreshTokenFactory();
    private Function<Token, Token> accessTokenFactory = new DefaultAccessTokenFactory();
    private Function<Token, String> refreshTokenStringSerializer = Objects::toString;
    private Function<Token, String> accessTokenStringSerializer = Objects::toString;
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (requestMatcher.matches(request)) {
            if (securityContextRepository.containsContext(request)) {
                SecurityContext context = securityContextRepository.loadDeferredContext(request).get();
                if (context != null && !(context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)) {

                    var refreshToken = refreshTokenFactory.apply(context.getAuthentication());
                    var accessToken = accessTokenFactory.apply(refreshToken);

                    var tokens = new Tokens(
                            accessTokenStringSerializer.apply(accessToken),
                            accessToken.expiresAt().toString(),
                            refreshTokenStringSerializer.apply(refreshToken),
                            refreshToken.expiresAt().toString());

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    objectMapper.writeValue(response.getWriter(), tokens);
                    return;
                }
            }
            throw new AccessDeniedException("User must be authenticated with JWT");
        }

        filterChain.doFilter(request, response);
    }
}
