package com.retailpulse.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = JwtConfig.class)
public class JwtConfigContextTest {
    @Autowired
    ApplicationContext ctx;

    @Autowired
    JWKSource<SecurityContext> jwkSource;

    @Test
    void bean_isSingleton_and_selectIsStableWithinBean() throws Exception {
        assertThat(jwkSource).isNotNull();

        var selector = new JWKSelector(new JWKMatcher.Builder().keyType(KeyType.RSA).build());

        List<JWK> first = jwkSource.get(selector, null);
        List<JWK> second = jwkSource.get(selector, null);

        assertThat(first).hasSize(1);
        assertThat(second).hasSize(1);

        String kid1 = first.getFirst().getKeyID();
        String kid2 = second.getFirst().getKeyID();
        assertThat(kid1).isEqualTo(kid2);

        // Confirm singleton scope
        var again = ctx.getBean(JWKSource.class);
        assertThat(again).isSameAs(jwkSource);
    }
}
