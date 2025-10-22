package com.retailpulse.config;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

public class GlobalModelAttributesUnitTest {

    @Test
    void urlPrefix_returns_value_from_field() {
        GlobalModelAttributes advice = new GlobalModelAttributes();
        ReflectionTestUtils.setField(advice, "urlPrefix", "/custom-prefix");

        assertThat(advice.urlPrefix()).isEqualTo("/custom-prefix");
    }
}
