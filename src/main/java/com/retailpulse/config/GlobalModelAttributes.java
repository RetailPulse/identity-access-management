package com.retailpulse.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class GlobalModelAttributes {

    @Value("${server.urlPrefix:/auth}")
    private String urlPrefix;

    @ModelAttribute("urlPrefix")
    public String urlPrefix() {
        return urlPrefix;
    }
}
