package org.rsinitsyn.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.rsinitsyn.Token;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
public class AccessTokenJwsStringDeserializer implements Function<String, Token> {

    private JWSVerifier jwsVerifier;

    public AccessTokenJwsStringDeserializer(JWSVerifier jwsVerifier) {
        this.jwsVerifier = jwsVerifier;
    }

    @Override
    public Token apply(String token) {
        try {
            var signedJWT = SignedJWT.parse(token);
            if (signedJWT.verify(jwsVerifier)) {
                var jwtClaimsSet = signedJWT.getJWTClaimsSet();
                return new Token(UUID.fromString(jwtClaimsSet.getJWTID()),
                        jwtClaimsSet.getSubject(),
                        jwtClaimsSet.getStringListClaim("authorities"),
                        jwtClaimsSet.getIssueTime().toInstant(),
                        jwtClaimsSet.getExpirationTime().toInstant());
            }
        } catch (ParseException | JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
