package com.retailpulse;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

public class RetailPulseIdentityAccessMgmtApplicationTest {

    @Test
    void main_invokesSpringApplicationRun_withArgs() {
        String[] args = {"--spring.profiles.active=test"};

        try (MockedStatic<SpringApplication> mocked = Mockito.mockStatic(SpringApplication.class)) {
            ConfigurableApplicationContext ctx = Mockito.mock(ConfigurableApplicationContext.class);

            mocked.when(() -> SpringApplication.run(
                    Mockito.eq(RetailPulseIdentityAccessMgmtApplication.class),
                    Mockito.any()
            )).thenReturn(ctx);

            // Call main
            RetailPulseIdentityAccessMgmtApplication.main(args);

            mocked.verify(() -> SpringApplication.run(
                    Mockito.eq(RetailPulseIdentityAccessMgmtApplication.class),
                    Mockito.any()
            ));
        }
    }

    @Test
    void class_isAnnotatedWithSpringBootApplication() {
        boolean hasAnnotation = RetailPulseIdentityAccessMgmtApplication.class
                .isAnnotationPresent(SpringBootApplication.class);
        assertThat(hasAnnotation).isTrue();
    }
}
