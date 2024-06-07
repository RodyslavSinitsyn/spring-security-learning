package org.rsinitsyn;

public record Tokens(String accessToken, String accessTokenExpiry, String refreshToken, String refreshTokenExpiry) {
}
