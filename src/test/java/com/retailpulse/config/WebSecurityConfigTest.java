package com.retailpulse.config;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.test.util.ReflectionTestUtils;

import javax.sql.DataSource;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

public class WebSecurityConfigTest {

    private final WebSecurityConfig cfg = new WebSecurityConfig();

    // ---------- PasswordEncoder ----------

    @Test
    void passwordEncoder_isBCrypt_andMatches() {
        PasswordEncoder encoder = cfg.passwordEncoder();
        assertThat(encoder).isNotNull();
        String hash = encoder.encode("secret");
        assertThat(hash).startsWith("$2"); // BCrypt prefix
        assertThat(encoder.matches("secret", hash)).isTrue();
        assertThat(encoder.matches("wrong", hash)).isFalse();
    }

    // ---------- AuthenticationManager ----------

    @Test
    void authenticationManager_delegatesToAuthenticationConfiguration() throws Exception {
        AuthenticationManager mockAm = mock(AuthenticationManager.class);
        AuthenticationConfiguration mockConfig = mock(AuthenticationConfiguration.class);
        when(mockConfig.getAuthenticationManager()).thenReturn(mockAm);

        AuthenticationManager bean = cfg.authenticationManager(mockConfig);

        assertThat(bean).isSameAs(mockAm);
        verify(mockConfig).getAuthenticationManager();
    }

    // ---------- UserDetailsService (JdbcUserDetailsManager) ----------

    @Test
    void userDetailsService_loadsUser_usingCustomQueries_againstH2() {
        DataSource ds = inMemoryDataSource();
        initSchemaAndData(ds);

        UserDetailsService uds = cfg.userDetailsService(ds);

        // sanity: we set custom queries
        assertCustomQueriesOn((JdbcUserDetailsManager) uds);

        // Load existing user
        UserDetails alice = uds.loadUserByUsername("alice");
        assertThat(alice.getUsername()).isEqualTo("alice");
        assertThat(alice.isEnabled()).isTrue();
        assertThat(alice.getPassword()).startsWith("$2"); // BCrypt

        Collection<? extends GrantedAuthority> authorities = alice.getAuthorities();
        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER");

        // Non-existent user
        assertThatThrownBy(() -> uds.loadUserByUsername("missing"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    private static DataSource inMemoryDataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.h2.Driver");
        // keep the DB alive for the duration of this JVM
        ds.setUrl("jdbc:h2:mem:testdb;MODE=MySQL;DB_CLOSE_DELAY=-1");
        ds.setUsername("sa");
        ds.setPassword("");
        return ds;
    }

    private void initSchemaAndData(DataSource ds) {
        JdbcTemplate tpl = new JdbcTemplate(ds);

        // Minimal schema that matches your custom queries
        tpl.execute("""
                CREATE TABLE users(
                  username VARCHAR(50) PRIMARY KEY,
                  password VARCHAR(100) NOT NULL,
                  enabled BOOLEAN NOT NULL
                )
                """);
        tpl.execute("""
                CREATE TABLE authorities(
                  username VARCHAR(50) NOT NULL,
                  authority VARCHAR(50) NOT NULL
                )
                """);
        tpl.execute("CREATE UNIQUE INDEX ix_auth_username ON authorities(username, authority)");

        // Insert one user with BCrypt password
        String hash = cfg.passwordEncoder().encode("secret");
        tpl.update("INSERT INTO users(username,password,enabled) VALUES (?,?,?)",
                "alice", hash, true);
        tpl.update("INSERT INTO authorities(username,authority) VALUES (?,?)",
                "alice", "ROLE_USER");
    }

    private void assertCustomQueriesOn(JdbcUserDetailsManager mgr) {
        // JdbcUserDetailsManager keeps the queries in fields with these names.
        // If the getters are present in your Spring Security version, prefer them.
        Object usersQuery = ReflectionTestUtils.getField(mgr, "usersByUsernameQuery");
        Object authsQuery = ReflectionTestUtils.getField(mgr, "authoritiesByUsernameQuery");

        assertThat(usersQuery).as("usersByUsernameQuery").isEqualTo(
                "select username, password, enabled from users where username = ?"
        );
        assertThat(authsQuery).as("authoritiesByUsernameQuery").isEqualTo(
                "select username, authority from authorities where username = ?"
        );
    }
}
