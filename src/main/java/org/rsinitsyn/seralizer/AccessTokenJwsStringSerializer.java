package org.rsinitsyn.seralizer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.rsinitsyn.Token;

import java.util.Date;
import java.util.function.Function;

@Slf4j
public class AccessTokenJwsStringSerializer implements Function<Token, String> {

    private JWSSigner jwsSigner;
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner) {
        this.jwsSigner = jwsSigner;
    }

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner, JWSAlgorithm jwsAlgorithm) {
        this.jwsSigner = jwsSigner;
        this.jwsAlgorithm = jwsAlgorithm;
    }

    @Override
    public String apply(Token token) {
        var jwtHeader = new JWSHeader.Builder(jwsAlgorithm).keyID(token.id().toString()).build();
        var claimsSet = new JWTClaimsSet.Builder()
                .subject(token.subject())
                .jwtID(token.id().toString())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();

        var signedJWT = new SignedJWT(jwtHeader, claimsSet);

        try {
            signedJWT.sign(jwsSigner);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            log.error(e.getMessage(), e);
        }

        return null;
    }
}
