package org.example.springsecurity.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class AppAuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");

        String message = "Error! Invalid access token or access denied.";
        String timestamp = ZonedDateTime.now(ZoneId.of("Asia/Dhaka"))
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ssa z"));

        String jsonPayload = """
                {
                    "message" : "%s",
                    "timestamp" : "%s"
                }""";

        response.getOutputStream().println(String.format(jsonPayload, message, timestamp));
    }
}
