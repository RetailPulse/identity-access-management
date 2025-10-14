package com.retailpulse.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("${server.urlPrefix:}") 
public class LoginController {

    @GetMapping("/rp-login")
    public String loginPage() {
        return "login"; // Thymeleaf template (login.html)
    }
}
