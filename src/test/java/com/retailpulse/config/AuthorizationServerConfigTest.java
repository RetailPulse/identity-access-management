package com.retailpulse.config;


import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(
        classes = {
                AuthorizationServerConfigTest.TestApp.class,
                AuthorizationServerConfig.class,
                AuthorizationServerConfigTest.TestSupport.class
        },
        properties = {
                // used by @Value("${auth.origin}") in CORS setup
                "auth.origin=http://localhost"
        }
)
@AutoConfigureMockMvc
public class AuthorizationServerConfigTest {

    @SpringBootApplication
    static class TestApp {}

    @TestConfiguration
    static class TestSupport {

        @RestController
        static class TestLoginController {
            @GetMapping("/rp-login")
            public String login() { return "ok"; }
        }

        /** Simple endpoint to prove app chain redirects to login when unauthenticated. */
        @RestController
        static class HelloController {
            @GetMapping("/hello")
            public String hello() { return "hi"; }
        }

        @Bean
        DataSource dataSource() {
            DriverManagerDataSource ds = new DriverManagerDataSource();
            ds.setDriverClassName("org.h2.Driver");
            ds.setUrl("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
            ds.setUsername("sa");
            ds.setPassword("");
            return ds;
        }
    }

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AuthorizationServerSettings authorizationServerSettings;
    @Autowired
    JdbcTemplate jdbcTemplate;
    @Autowired
    JdbcOperations jdbcOperations;
    @Autowired
    JdbcOAuth2AuthorizationService authorizationService;
    @Autowired
    JdbcOAuth2AuthorizationConsentService authorizationConsentService;
    @Autowired
    OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer;
    @MockitoBean
    RegisteredClientRepository registeredClientRepository;

    @BeforeEach
    void setupClientStub() {
        RegisteredClient testClient = RegisteredClient.withId("id-1")
                .clientId("test-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/callback")
                .scope("openid")
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .build();

        when(registeredClientRepository.findByClientId("test-client")).thenReturn(testClient);
    }

    @Test
    @DisplayName("Sanity: core beans are present")
    void beansPresent() {
        assertThat(authorizationServerSettings).isNotNull();
        assertThat(jdbcTemplate).isNotNull();
        assertThat(jdbcOperations).isNotNull();
        assertThat(registeredClientRepository).isNotNull();
        assertThat(authorizationService).isNotNull();
        assertThat(authorizationConsentService).isNotNull();
        assertThat(jwtTokenCustomizer).isNotNull();
    }

    @Test
    @DisplayName("Default chain: protected endpoint redirects to /rp-login")
    void defaultChain_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/hello"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, Matchers.endsWith("/rp-login")));
    }

    @Test
    @DisplayName("Default chain: CSRF disabled → POST to protected endpoint also redirects to /rp-login (not 403)")
    void defaultChain_postAlsoRedirectsToLogin() throws Exception {
        mockMvc.perform(post("/hello"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, Matchers.endsWith("/rp-login")));
    }

    @Test
    @DisplayName("Login page is reachable (permitAll) and returns 200")
    void loginPage_isPermitAll() throws Exception {
        mockMvc.perform(get("/rp-login"))
                .andExpect(status().isOk())
                .andExpect(content().string("ok"));
    }

    @Test
    void asEndpoints_redirectToLogin_onValidUnauthenticatedAuthorize() throws Exception {
        String url = org.springframework.web.util.UriComponentsBuilder
                .fromPath("/oauth2/authorize")
                .queryParam("response_type","code")
                .queryParam("client_id","test-client")
                .queryParam("redirect_uri","http://localhost/callback")
                .queryParam("scope","openid")
                .queryParam("state","xyz")
                .build(true)  // keep encoded
                .toUriString();

        mockMvc.perform(get(url).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, Matchers.endsWith("/rp-login")));
    }

    @Test
    @DisplayName("AS chain: malformed /oauth2/authorize is 400 (parameter validation happens before auth)")
    void asEndpoints_malformedAuthorize_is400() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("AS chain: CORS preflight hits entry point → redirects to /rp-login")
    void asEndpoints_corsPreflight() throws Exception {
        mockMvc.perform(options("/oauth2/authorize")
                        .header("Origin", "http://localhost")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, Matchers.endsWith("/rp-login")));
    }

    @Test
    @DisplayName("AS chain: CSRF is ignored for AS endpoints → POST /oauth2/token is 4xx but not 403 CSRF")
    void asEndpoints_csrfIgnored() throws Exception {
        mockMvc.perform(post("/oauth2/token"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, Matchers.containsString("/rp-login")));
    }

    @Test
    @DisplayName("jwtTokenCustomizer: adds 'roles' claim for ACCESS_TOKEN (without ROLE_ prefix)")
    void jwtCustomizer_addsRolesForAccessToken() {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder();

        var ctx = Mockito.mock(org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext.class);
        when(ctx.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);

        Authentication principal = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "user", "pw", AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER"));
        when(ctx.getPrincipal()).thenReturn(principal);
        when(ctx.getClaims()).thenReturn(claims);

        jwtTokenCustomizer.customize(ctx);

        Map<String, Object> out = claims.build().getClaims();

        assertThat(out).containsKey("roles");
        @SuppressWarnings("unchecked")
        Set<String> roles = (Set<String>) out.get("roles");
        assertThat(roles).containsExactlyInAnyOrder("ADMIN", "USER");

        assertThat(out.get("roles")).isInstanceOf(java.util.Set.class);
    }

    @Test
    @DisplayName("jwtTokenCustomizer: no-op for non-ACCESS token types")
    void jwtCustomizer_noopForOtherTokenTypes() {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .claim("seed", "1");

        JwtEncodingContext ctx = Mockito.mock(JwtEncodingContext.class);
        when(ctx.getTokenType()).thenReturn(new OAuth2TokenType("id_token"));
        when(ctx.getClaims()).thenReturn(claims);

        Authentication principal =
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        "user", "pw", AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
        when(ctx.getPrincipal()).thenReturn(principal);

        // Act
        jwtTokenCustomizer.customize(ctx);

        // Assert
        Map<String, Object> out = claims.build().getClaims();
        assertThat(out).containsEntry("seed", "1");
        assertThat(out).doesNotContainKey("roles");
    }
}
