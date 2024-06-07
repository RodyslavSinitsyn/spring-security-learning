package org.rsinitsyn.seralizer;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import org.rsinitsyn.Token;

import java.util.Date;
import java.util.function.Function;

@Slf4j
public class RefreshTokenJwtStringSerializer implements Function<Token, String> {

    private JWEEncrypter jweEncrypter;
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128CBC_HS256;

    public RefreshTokenJwtStringSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    public RefreshTokenJwtStringSerializer(JWEEncrypter jweEncrypter, JWEAlgorithm jweAlgorithm, EncryptionMethod encryptionMethod) {
        this.jweEncrypter = jweEncrypter;
        this.jweAlgorithm = jweAlgorithm;
        this.encryptionMethod = encryptionMethod;
    }

    @Override
    public String apply(Token token) {
        var jweHeader = new JWEHeader.Builder(jweAlgorithm, encryptionMethod).keyID(token.id().toString()).build();
        var claimsSet = new JWTClaimsSet.Builder()
                .subject(token.subject())
                .jwtID(token.id().toString())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();

        var encryptedJWT = new EncryptedJWT(jweHeader, claimsSet);

        try {
            encryptedJWT.encrypt(jweEncrypter);

            return encryptedJWT.serialize();
        } catch (JOSEException e) {
            log.error(e.getMessage(), e);
        }

        return null;
    }
}
