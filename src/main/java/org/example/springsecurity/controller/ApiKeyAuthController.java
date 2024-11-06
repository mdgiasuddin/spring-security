package org.example.springsecurity.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.springsecurity.model.dto.request.LoginRequest;
import org.example.springsecurity.model.dto.response.LoginResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/api-key-auth")
public class ApiKeyAuthController {
    @PostMapping("/login")
    public LoginResponse login(@RequestBody @Valid LoginRequest request) {
        log.info("ApiKeyAuthController: Login request: {}", request);
        return new LoginResponse(UUID.randomUUID().toString().replace("-", ""));
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/admin")
    public String greetAdmin() {
        log.info("ApiKeyAuthController: greetAdmin");
        return "Hello Admin! Welcome.";
    }

    @PreAuthorize("hasAnyRole('USER')")
    @GetMapping("/user")
    public String greetUser() {
        log.info("ApiKeyAuthController: greetUser");
        return "Hello User! Welcome.";
    }
}
