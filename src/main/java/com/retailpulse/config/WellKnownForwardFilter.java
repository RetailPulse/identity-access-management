package com.retailpulse.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class WellKnownForwardFilter extends OncePerRequestFilter {

    @Value("${server.urlPrefix:/auth}")
    private String urlPrefix;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        if (requestURI.equals(urlPrefix + "/.well-known/openid-configuration")) {
            request.getRequestDispatcher("/.well-known/openid-configuration").forward(request, response);
            return;
        }

        if (requestURI.equals(urlPrefix + "/oauth2/jwks")) {
            request.getRequestDispatcher("/oauth2/jwks").forward(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
