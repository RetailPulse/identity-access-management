package com.retailpulse.controller;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class LoginControllerStandaloneTest {
    @Test
    void rpLogin_returns_login_view() throws Exception {
        MockMvc mvc = MockMvcBuilders
                .standaloneSetup(new LoginController())
                .setViewResolvers(viewResolver())
                .build();

        mvc.perform(get("/rp-login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    private ViewResolver viewResolver() {
        InternalResourceViewResolver r = new InternalResourceViewResolver();
        r.setPrefix("/templates/");
        r.setSuffix(".html");
        return r;
    }
}
