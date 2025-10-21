package com.retailpulse.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtConfigTest {

    @Test
    void jwkSource_returnsRsaKey_withPrivate_and2048bits() throws Exception {
        JwtConfig cfg = new JwtConfig();

        var source = cfg.jwkSource();
        assertThat(source).isNotNull();

        var selector = new JWKSelector(new JWKMatcher.Builder().keyType(KeyType.RSA).build());
        List<JWK> jwks = source.get(selector, null);

        assertThat(jwks).hasSize(1);
        assertThat(jwks.getFirst()).isInstanceOf(RSAKey.class);

        RSAKey rsa = (RSAKey) jwks.getFirst();
        assertThat(rsa.getKeyID()).isNotBlank();
        assertThat(rsa.isPrivate()).isTrue();
        assertThat(rsa.toRSAPrivateKey()).isNotNull();

        RSAPublicKey pub = rsa.toRSAPublicKey();
        assertThat(pub.getModulus().bitLength()).isGreaterThanOrEqualTo(2048);
    }
}
