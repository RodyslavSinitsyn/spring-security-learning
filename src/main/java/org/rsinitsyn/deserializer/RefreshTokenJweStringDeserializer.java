package org.rsinitsyn.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.extern.slf4j.Slf4j;
import org.rsinitsyn.Token;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
public class RefreshTokenJweStringDeserializer implements Function<String, Token> {

    private JWEDecrypter jweDecrypter;

    public RefreshTokenJweStringDeserializer(JWEDecrypter jweDecrypter) {
        this.jweDecrypter = jweDecrypter;
    }

    @Override
    public Token apply(String token) {
        try {
            var encryptedJWT = EncryptedJWT.parse(token);
            encryptedJWT.decrypt(jweDecrypter);
            var jwtClaimsSet = encryptedJWT.getJWTClaimsSet();
            return new Token(UUID.fromString(jwtClaimsSet.getJWTID()),
                    jwtClaimsSet.getSubject(),
                    jwtClaimsSet.getStringListClaim("authorities"),
                    jwtClaimsSet.getIssueTime().toInstant(),
                    jwtClaimsSet.getExpirationTime().toInstant());
        } catch (ParseException | JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
