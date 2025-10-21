package com.retailpulse.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(
        properties = {
                "auth.origin=http://test-origin",
                // keep defaults for other props
        }
)
@AutoConfigureMockMvc
@Import(AuthorizationServerConfigTest.TestStubs.class)
public class AuthorizationServerConfigTest {

        @Autowired
        MockMvc mvc;
        @Autowired
        JdbcTemplate jdbcTemplate;

        // ---------- Default chain (order=2) ----------
        @Test
        void login_page_is_permitted_and_accessible() throws Exception {
                mvc.perform(get("/rp-login"))
                        .andExpect(status().isOk())
                        .andExpect(content().string("LOGIN"));
        }

        @Test
        void protected_path_requires_auth_redirects_to_login() throws Exception {
                mvc.perform(get("/protected"))
                        .andExpect(status().isFound())
                        .andExpect(redirectedUrlPattern("**/rp-login"));
        }

        @Test
        void protected_path_with_user_is_ok() throws Exception {
                mvc.perform(get("/protected").with(SecurityMockMvcRequestPostProcessors.user("alice")))
                        .andExpect(status().isOk())
                        .andExpect(content().string("PROTECTED"));
        }

        @Test
        void static_like_path_is_permitted() throws Exception {
                mvc.perform(get("/css/site.css"))
                        // even if the controller returns 200, the important bit is: not a 302/401 from security
                        .andExpect(status().isOk())
                        .andExpect(content().string("CSS"));
        }

        // ---------- Authorization Server chain (order=1) ----------
        @Test
        void as_endpoint_authorize_requires_auth_redirects_to_login() throws Exception {
                // Minimal params; security should kick in first and redirect to login
                mvc.perform(get("/oauth2/authorize")
                                .param("response_type", "code")
                                .param("client_id", "test-client")
                                .param("redirect_uri", "https://client.example/callback")
                                .param("scope", "openid"))
                        .andExpect(status().isFound())
                        .andExpect(redirectedUrlPattern("**/rp-login"));
        }

        @Test
        void cors_preflight_on_as_endpoint_returns_allow_origin_header() throws Exception {
                mvc.perform(options("/oauth2/authorize")
                                .header("Origin", "http://test-origin")
                                .header("Access-Control-Request-Method", "GET"))
                        // Spring may return 200 or 204 for preflight; accept either, but must include CORS header.
                        .andExpect(header().string("Access-Control-Allow-Origin", "http://test-origin"));
        }

        @Test
        void csrf_ignored_on_as_token_endpoint_not_403() throws Exception {
                // No CSRF token; should NOT be 403, though likely 400/401 due to client auth
                mvc.perform(post("/oauth2/token")
                                .contentType(APPLICATION_FORM_URLENCODED))
                        .andExpect(status().is4xxClientError())
                        .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(403));
        }

        // ---------- Beans: JdbcTemplate queryTimeout ----------
        @Test
        void jdbcTemplate_has_queryTimeout_30() {
                // The field is protected internally; reflect for a precise check
                Integer timeout = (Integer) org.springframework.test.util.ReflectionTestUtils
                        .getField(jdbcTemplate, "queryTimeout");
                assertThat(timeout).isEqualTo(30);
        }

        // ---------- Test wiring ----------
        @TestConfiguration
        static class TestStubs {

                // Minimal DataSource for jdbc beans in config
                @Bean
                DataSource ds() {
                        var ds = new DriverManagerDataSource();
                        ds.setDriverClassName("org.h2.Driver");
                        ds.setUrl("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1");
                        ds.setUsername("sa");
                        ds.setPassword("");
                        return ds;
                }

                // Minimal RegisteredClient so /oauth2/authorize can parse params without NPE
                @Bean
                RegisteredClientRepository registeredClientRepository() {
                        var client = withId("id-1")
                                .clientId("test-client")
                                .clientSecret("{noop}secret")
                                .authorizationGrantType(AUTHORIZATION_CODE)
                                .redirectUri("https://client.example/callback")
                                .scope("openid")
                                .build();
                        return new InMemoryRegisteredClientRepository(client);
                }

                // A user store so @WithMockUser or .with(user(...)) can authenticate
                @Bean
                InMemoryUserDetailsManager users() {
                        UserDetails u = User.withUsername("alice").password("{noop}pw").roles("USER").build();
                        return new InMemoryUserDetailsManager(u);
                }

                // Small stub controller to make routes concrete (so we can assert 200)
                @RestController
                static class StubControllers {
                        @GetMapping("/rp-login")
                        public String login() { return "LOGIN"; }

                        @GetMapping("/protected")
                        public String protectedEcho() { return "PROTECTED"; }

                        @GetMapping("/css/site.css")
                        public String css() { return "CSS"; }
                }
        }
}
