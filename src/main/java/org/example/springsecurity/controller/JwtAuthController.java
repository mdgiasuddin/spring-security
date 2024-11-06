package org.example.springsecurity.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.springsecurity.model.dto.request.LoginRequest;
import org.example.springsecurity.model.dto.response.LoginResponse;
import org.example.springsecurity.service.JwtAuthService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/jwt-auth")
@RequiredArgsConstructor
public class JwtAuthController {

    private final JwtAuthService jwtAuthService;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody @Valid LoginRequest request) {
        log.info("JwtApiController: Login request: {}", request);
        return jwtAuthService.login(request);
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/admin")
    public String greetAdmin() {
        log.info("JwtApiController: greetAdmin");
        return "Hello Admin! Welcome.";
    }

    @PreAuthorize("hasAnyRole('USER')")
    @GetMapping("/user")
    public String greetUser() {
        log.info("JwtApiController: greetUser");
        return "Hello User! Welcome.";
    }
}
