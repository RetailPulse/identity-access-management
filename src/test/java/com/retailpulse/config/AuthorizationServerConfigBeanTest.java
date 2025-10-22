package com.retailpulse.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.set;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthorizationServerConfigBeanTest {

    private final AuthorizationServerConfig cfg = new AuthorizationServerConfig();

    @Test
    void adds_roles_claim_for_access_tokens() {
        var auth = new UsernamePasswordAuthenticationToken(
                "u", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER")
        );

        var builder = JwtClaimsSet.builder();
        var ctx = org.mockito.Mockito.mock(JwtEncodingContext.class);
        org.mockito.Mockito.when(ctx.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        org.mockito.Mockito.when(ctx.getPrincipal()).thenReturn(auth);
        org.mockito.Mockito.when(ctx.getClaims()).thenReturn(builder);

        cfg.jwtTokenCustomizer().customize(ctx);

        Map<String, Object> claims = builder.build().getClaims();
        assertThat(claims).containsKey("roles");
        Object rolesObj = claims.get("roles");
        assertThat(rolesObj)
                .asInstanceOf(set(String.class))
                .containsExactlyInAnyOrder("ADMIN", "USER");
    }

    @Test
    void access_token_with_no_authorities_produces_empty_roles_set() {
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuer("https://issuer");

        JwtEncodingContext ctx = mock(JwtEncodingContext.class);
        when(ctx.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(ctx.getClaims()).thenReturn(builder);

        Authentication principal = mock(Authentication.class);
        when(principal.getAuthorities()).thenReturn(Collections.emptyList());
        when(ctx.getPrincipal()).thenReturn(principal);

        cfg.jwtTokenCustomizer().customize(ctx);

        JwtClaimsSet claims = builder.build();

        Object rolesObj = claims.getClaims().get("roles");
        assertThat(rolesObj)
                .asInstanceOf(set(String.class))
                .isEmpty();
    }

    @Test
    void jwtCustomizer_addsRoles_forAccessTokenOnly() {
        AuthorizationServerConfig config = new AuthorizationServerConfig();

        OAuth2TokenCustomizer<JwtEncodingContext> customizer = (OAuth2TokenCustomizer<JwtEncodingContext>) config.jwtTokenCustomizer();

        JwtEncodingContext ctx = mock(JwtEncodingContext.class);
        when(ctx.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        var authorities = AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER");

        var auth = mock(org.springframework.security.core.Authentication.class);
        //noinspection unchecked
        when(auth.getAuthorities()).thenReturn(Collections.unmodifiableList(new ArrayList(authorities)));
        when(ctx.getPrincipal()).thenReturn(auth);

        JwtClaimsSet.Builder builder = mock(JwtClaimsSet.Builder.class);
        AtomicReference<Map<String, Object>> captured = new AtomicReference<>();
        when(builder.claims(any())).thenAnswer(inv -> {
            @SuppressWarnings("unchecked")
            var consumer = (java.util.function.Consumer<Map<String,Object>>) inv.getArgument(0);
            Map<String,Object> m = new HashMap<>();
            consumer.accept(m);
            captured.set(m);
            return builder;
        });
        when(ctx.getClaims()).thenReturn(builder);

        // Act
        customizer.customize(ctx);

        // Assert roles claim present and prefixes stripped
        Map<String, Object> claims = captured.get();
        assertThat(claims).isNotNull();
        assertThat(claims).containsKey("roles");
        @SuppressWarnings("unchecked")
        Set<String> roles = (Set<String>) claims.get("roles");
        assertThat(roles).containsExactlyInAnyOrder("ADMIN", "USER");
    }

}
