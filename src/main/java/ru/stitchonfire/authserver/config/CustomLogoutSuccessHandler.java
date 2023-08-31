package ru.stitchonfire.authserver.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.io.IOException;

@AllArgsConstructor
public class CustomLogoutSuccessHandler extends
        SimpleUrlLogoutSuccessHandler implements LogoutSuccessHandler {
    private final String url;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse
            response, Authentication authentication)
            throws IOException {
        if (authentication != null) {
            System.out.println(authentication.getName());
        }
        response.setStatus(HttpStatus.OK.value());
        response.sendRedirect(url);
    }
}
