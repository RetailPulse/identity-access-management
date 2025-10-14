package com.retailpulse.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("${server.urlPrefix:}") 
public class WellKnownForwardController {

    @GetMapping("/.well-known/openid-configuration")
    public String forwardOpenIdConfiguration() {
        // forward internally (no redirect, stays within server)
        return "forward:/.well-known/openid-configuration";
    }

    @GetMapping("/oauth2/jwks")
    public String forwardJwks() {
        return "forward:/oauth2/jwks";
    }
}
