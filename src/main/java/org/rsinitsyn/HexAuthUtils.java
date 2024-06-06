package org.rsinitsyn;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Hex;

import java.nio.charset.StandardCharsets;

@UtilityClass
public class HexAuthUtils {

    public Authentication getAuthFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Hex ")) {
            var rawToken = authHeader.replaceAll("^Hex ", "");
            var token = new String(Hex.decode(rawToken), StandardCharsets.UTF_8);
            String[] tokenParts = token.split(":");

            return UsernamePasswordAuthenticationToken
                    .unauthenticated(tokenParts[0], tokenParts[1]);
        }

        return null;
    }
}
