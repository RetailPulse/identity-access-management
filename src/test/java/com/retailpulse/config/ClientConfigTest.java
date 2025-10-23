package com.retailpulse.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.*;

public class ClientConfigTest {
    private ClientConfig config;

    private final String clientId = "web-client";
    private final String clientName = "RetailPulse Web";
    private final String redirectUri = "http://localhost:4200/login/oauth2/code/retailpulse";
    private final String postLogoutRedirectUri = "http://localhost:4200/";

    @BeforeEach
    void setUp() {
        config = new ClientConfig();
        ReflectionTestUtils.setField(config, "clientId", clientId);
        ReflectionTestUtils.setField(config, "clientName", clientName);
        ReflectionTestUtils.setField(config, "redirectUri", redirectUri);
        ReflectionTestUtils.setField(config, "postLogoutRedirectUri", postLogoutRedirectUri);
    }

    @Test
    void initializeClients_savesWhenMissing() throws Exception {
        RegisteredClientRepository repo = mock(RegisteredClientRepository.class);
        when(repo.findByClientId(clientId)).thenReturn(null);

        // When
        var runner = config.initializeClients(repo);
        runner.run();

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo).save(captor.capture());
        RegisteredClient saved = captor.getValue();

        assertThat(saved.getClientId()).isEqualTo(clientId);
        assertThat(saved.getClientName()).isEqualTo(clientName);

        assertThat(saved.getClientAuthenticationMethods())
                .contains(ClientAuthenticationMethod.NONE);
        assertThat(saved.getAuthorizationGrantTypes())
                .contains(AuthorizationGrantType.AUTHORIZATION_CODE);

        // Redirects
        assertThat(saved.getRedirectUris()).contains(redirectUri);
        assertThat(saved.getPostLogoutRedirectUris()).contains(postLogoutRedirectUri);

        // Scopes
        assertThat(saved.getScopes()).contains(OidcScopes.OPENID);

        // Client settings (PKCE + consent)
        ClientSettings cs = saved.getClientSettings();
        assertThat(cs.isRequireProofKey()).isTrue();
        assertThat(cs.isRequireAuthorizationConsent()).isTrue();

        // Token settings (TTL)
        TokenSettings ts = saved.getTokenSettings();
        assertThat(ts.getAuthorizationCodeTimeToLive()).isEqualTo(Duration.ofMinutes(5));
        assertThat(ts.getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(3));

        // Issued-at is set
        Instant issuedAt = saved.getClientIdIssuedAt();
        assertThat(issuedAt).isNotNull();
        assert issuedAt != null;
        assertThat(Duration.between(issuedAt, Instant.now()).abs()).isLessThan(Duration.ofMinutes(5));
    }

    @Test
    void initializeClients_skipsWhenAlreadyExists() throws Exception {
        RegisteredClientRepository repo = mock(RegisteredClientRepository.class);
        RegisteredClient existing = RegisteredClient.withId("id-1")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .redirectUri(redirectUri)
                .postLogoutRedirectUri(postLogoutRedirectUri)
                .scope(OidcScopes.OPENID)
                .build();

        when(repo.findByClientId(clientId)).thenReturn(existing);

        var runner = config.initializeClients(repo);
        runner.run();

        verify(repo, never()).save(any());
    }

    @Test
    void initializeClients_doesNotThrowWhenRepositoryFails() {
        RegisteredClientRepository repo = mock(RegisteredClientRepository.class);
        when(repo.findByClientId(clientId)).thenReturn(null);
        doThrow(new RuntimeException("DB down")).when(repo).save(any(RegisteredClient.class));

        var runner = config.initializeClients(repo);
        Executable exec = runner::run;

        assertDoesNotThrow(exec);
    }

    @Test
    void registeredClientRepository_factoryReturnsJdbcImplementation() {
        JdbcOperations jdbc = mock(JdbcOperations.class);

        RegisteredClientRepository bean = config.registeredClientRepository(jdbc);

        assertThat(bean).isInstanceOf(JdbcRegisteredClientRepository.class);
    }
}
