package com.retailpulse.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@WebMvcTest(controllers = LoginController.class)
@AutoConfigureMockMvc(addFilters = false)
public class LoginControllerTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void rpLogin_returns_login_view() throws Exception {
        mvc.perform(get("/rp-login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @TestConfiguration
    static class TestViews {
        @Bean
        InternalResourceViewResolver defaultViewResolver() {
            InternalResourceViewResolver r = new InternalResourceViewResolver();
            r.setPrefix("/templates/");
            r.setSuffix(".html");
            return r;
        }
    }
}
