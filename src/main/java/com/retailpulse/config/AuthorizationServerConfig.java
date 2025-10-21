package com.retailpulse.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class AuthorizationServerConfig {

  @Value("${auth.origin}")
  private String originURL;

  @Bean
  @Order(1)
  public SecurityFilterChain asFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer serverConfiguration = new OAuth2AuthorizationServerConfigurer();
    RequestMatcher endpoints = serverConfiguration.getEndpointsMatcher();

    http.securityMatcher(endpoints)
                    .authorizeHttpRequests( auth -> auth.anyRequest().authenticated())
                            .csrf( csrf -> csrf.ignoringRequestMatchers(endpoints))
    .exceptionHandling(e ->
      e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/rp-login"))
    )
    .cors(c -> c.configurationSource(corsConfigurationSource()))
            .with(serverConfiguration, conf -> conf.oidc(Customizer.withDefaults()));

    return http.build();
  }


  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
      .formLogin(form -> form
      .loginPage("/rp-login")
      .loginProcessingUrl("/login")
      .permitAll());

    http.csrf(AbstractHttpConfigurer::disable);

    http.authorizeHttpRequests(c -> c                
      .requestMatchers(
        "/login",
        "/images/**",
        "/css/**",
        "/js/**",
        "/actuator/info",
        "/actuator/prometheus",
        "/actuator/health"
      ).permitAll()
      .anyRequest().authenticated()
    );

    return http.build();
  }

  /**
   * CORS configuration source
   */
  private CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of(originURL));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    configuration.setExposedHeaders(List.of("Authorization"));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  /**
   * Configure Authorization Server endpoints with URL prefix
   */
  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  /**
   * JDBC template for Authorization Server persistence
   */
  @Bean
  public JdbcTemplate jdbcTemplate(DataSource dataSource) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    jdbcTemplate.setQueryTimeout(30);
    return jdbcTemplate;
  }

  @Bean
  public JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService(JdbcOperations jdbcOperations, 
    RegisteredClientRepository registeredClientRepository) {

    return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
  }

  @Bean
  public JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(
      JdbcOperations jdbcOperations,
      RegisteredClientRepository registeredClientRepository) {

      return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
  }

  /**
   * JWT token customizer to include roles
   */
  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
    return context -> {
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        context.getClaims().claims(claims -> {
          Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
            .stream()
            .map(c -> c.replaceFirst("^ROLE_", ""))
            .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
          claims.put("roles", roles);
        });
      }
    };
  }
}
