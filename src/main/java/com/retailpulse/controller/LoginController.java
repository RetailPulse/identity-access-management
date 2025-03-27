package com.retailpulse.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping("/rp-login")
    public String loginPage() {
        return "login"; // Thymeleaf template name (login.html)
    }
}
