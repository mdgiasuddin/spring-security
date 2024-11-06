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
@RequestMapping("/api/basic-auth")
public class BasicAuthController {

    @PostMapping("/login")
    public LoginResponse login(@RequestBody @Valid LoginRequest request) {
        log.info("BasicAuthController: Login request: {}", request);
        return new LoginResponse(UUID.randomUUID().toString().replace("-", ""));
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/admin")
    public String greetAdmin() {
        log.info("BasicAuthController: greetAdmin");
        return "Hello Admin! Welcome.";
    }

    @PreAuthorize("hasAnyRole('USER')")
    @GetMapping("/user")
    public String greetUser() {
        log.info("BasicAuthController: greetUser");
        return "Hello User! Welcome.";
    }
}
